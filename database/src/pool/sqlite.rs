use crate::pool::{Connection, ConnectionManager, ManagedConnection, Transaction};
use crate::{
    ArtifactId, Benchmark, BenchmarkData, CollectionId, Commit, CommitType, Date, Profile,
};
use crate::{ArtifactIdNumber, Index, QueryDatum, QueuedCommit};
use chrono::{DateTime, TimeZone, Utc};
use hashbrown::HashMap;
use rusqlite::params;
use rusqlite::OptionalExtension;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::Once;
use std::time::Duration;

pub struct SqliteTransaction<'a> {
    conn: &'a mut SqliteConnection,
    finished: bool,
}

#[async_trait::async_trait]
impl<'a> Transaction for SqliteTransaction<'a> {
    async fn commit(mut self: Box<Self>) -> Result<(), anyhow::Error> {
        self.finished = true;
        Ok(self.conn.raw().execute_batch("COMMIT")?)
    }

    async fn finish(mut self: Box<Self>) -> Result<(), anyhow::Error> {
        self.finished = true;
        Ok(self.conn.raw().execute_batch("ROLLBACK")?)
    }
    fn conn(&mut self) -> &mut dyn Connection {
        &mut *self.conn
    }
    fn conn_ref(&self) -> &dyn Connection {
        &*self.conn
    }
}

impl std::ops::Deref for SqliteTransaction<'_> {
    type Target = dyn Connection;
    fn deref(&self) -> &Self::Target {
        &*self.conn
    }
}

impl std::ops::DerefMut for SqliteTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn
    }
}

impl Drop for SqliteTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.conn.raw().execute_batch("ROLLBACK").unwrap();
        }
    }
}

pub struct Sqlite(PathBuf, Once);

impl Sqlite {
    pub fn new(path: PathBuf) -> Self {
        Sqlite(path, Once::new())
    }
}

struct Migration {
    /// One or more SQL statements, each terminated by a semicolon.
    sql: &'static str,

    /// If false, indicates that foreign key checking should be delayed until after execution of
    /// the migration SQL, and foreign key `ON UPDATE` and `ON DELETE` actions disabled completely.
    foreign_key_constraints_enabled: bool,
}

impl Migration {
    /// Returns a `Migration` with foreign key constraints enabled during execution.
    const fn new(sql: &'static str) -> Migration {
        Migration {
            sql,
            foreign_key_constraints_enabled: true,
        }
    }

    /// Returns a `Migration` with foreign key checking delayed until after execution, and foreign
    /// key `ON UPDATE` and `ON DELETE` actions disabled completely.
    ///
    /// SQLite has limited `ALTER TABLE` capabilities, so some schema alterations require the
    /// approach of replacing a table with a new one having the desired schema. Because there might
    /// be other tables with foreign key constraints on the table, these constraints need to be
    /// disabled during execution of such migration SQL, and reenabled after. Otherwise, dropping
    /// the old table may trigger `ON DELETE` actions in the referencing tables. See [SQLite
    /// documentation](https://www.sqlite.org/lang_altertable.html) for more information.
    const fn without_foreign_key_constraints(sql: &'static str) -> Migration {
        Migration {
            sql,
            foreign_key_constraints_enabled: false,
        }
    }

    fn execute(&self, conn: &mut rusqlite::Connection, migration_id: i32) {
        if self.foreign_key_constraints_enabled {
            let tx = conn.transaction().unwrap();
            tx.execute_batch(&self.sql).unwrap();
            tx.pragma_update(None, "user_version", &migration_id)
                .unwrap();
            tx.commit().unwrap();
            return;
        }

        // The following steps are reproduced from https://www.sqlite.org/lang_altertable.html,
        // from the section titled, "Making Other Kinds Of Table Schema Changes".

        // 1.  If foreign key constraints are enabled, disable them using PRAGMA foreign_keys=OFF.
        conn.pragma_update(None, "foreign_keys", &"OFF").unwrap();

        // 2.  Start a transaction.
        let tx = conn.transaction().unwrap();

        // The migration SQL is responsible for steps 3 through 9.

        // 3.  Remember the format of all indexes, triggers, and views associated with table X.
        //     This information will be needed in step 8 below. One way to do this is to run a
        //     query like the following: SELECT type, sql FROM sqlite_schema WHERE tbl_name='X'.
        //
        // 4.  Use CREATE TABLE to construct a new table "new_X" that is in the desired revised
        //     format of table X. Make sure that the name "new_X" does not collide with any
        //     existing table name, of course.
        //
        // 5.  Transfer content from X into new_X using a statement like: INSERT INTO new_X SELECT
        //     ... FROM X.
        //
        // 6.  Drop the old table X: DROP TABLE X.
        //
        // 7.  Change the name of new_X to X using: ALTER TABLE new_X RENAME TO X.
        //
        // 8.  Use CREATE INDEX, CREATE TRIGGER, and CREATE VIEW to reconstruct indexes, triggers,
        //     and views associated with table X. Perhaps use the old format of the triggers,
        //     indexes, and views saved from step 3 above as a guide, making changes as appropriate
        //     for the alteration.
        //
        // 9.  If any views refer to table X in a way that is affected by the schema change, then
        //     drop those views using DROP VIEW and recreate them with whatever changes are
        //     necessary to accommodate the schema change using CREATE VIEW.
        tx.execute_batch(&self.sql).unwrap();

        // 10. If foreign key constraints were originally enabled then run PRAGMA foreign_key_check
        //     to verify that the schema change did not break any foreign key constraints.
        tx.pragma_query(None, "foreign_key_check", |row| {
            let table: String = row.get_unwrap(0);
            let row_id: Option<i64> = row.get_unwrap(1);
            let foreign_table: String = row.get_unwrap(2);
            let fk_idx: i64 = row.get_unwrap(3);

            tx.query_row::<(), _, _>(
                "select * from pragma_foreign_key_list(?) where id = ?",
                params![&table, &fk_idx],
                |row| {
                    let col: String = row.get_unwrap(3);
                    let foreign_col: String = row.get_unwrap(4);
                    panic!(
                        "Foreign key violation encountered during migration\n\
                            table: {},\n\
                            column: {},\n\
                            row_id: {:?},\n\
                            foreign table: {},\n\
                            foreign column: {}\n\
                            migration ID: {}\n",
                        table, col, row_id, foreign_table, foreign_col, migration_id,
                    );
                },
            )
            .unwrap();
            Ok(())
        })
        .unwrap();

        tx.pragma_update(None, "user_version", &migration_id)
            .unwrap();

        // 11. Commit the transaction started in step 2.
        tx.commit().unwrap();

        // 12. If foreign keys constraints were originally enabled, reenable them now.
        conn.pragma_update(None, "foreign_keys", &"ON").unwrap();
    }
}

static MIGRATIONS: &[Migration] = &[
    Migration::new(""),
    Migration::new(
        r#"
        create table benchmark(
            name text primary key,
            -- Whether this benchmark supports stable
            stabilized bool not null
        );
        create table artifact(
            id integer primary key not null,
            name text not null unique,
            date integer,
            type text not null
        );
        create table collection(
            id integer primary key not null
        );
        create table error_series(
            id integer primary key not null,
            crate text not null unique references benchmark(name) on delete cascade on update cascade
        );
        create table error(
            series integer not null references error_series(id) on delete cascade on update cascade,
            aid integer not null references artifact(id) on delete cascade on update cascade,
            error text,
            PRIMARY KEY(series, aid)
        );
        create table pstat_series(
            id integer primary key not null,
            crate text not null references benchmark(name) on delete cascade on update cascade,
            profile text not null,
            cache text not null,
            statistic text not null,
            UNIQUE(crate, profile, cache, statistic)
        );
        create table pstat(
            series integer references pstat_series(id) on delete cascade on update cascade,
            aid integer references artifact(id) on delete cascade on update cascade,
            cid integer references collection(id) on delete cascade on update cascade,
            value double not null,
            PRIMARY KEY(series, aid, cid)
        );
        create table self_profile_query_series(
            id integer primary key not null,
            crate text not null references benchmark(name) on delete cascade on update cascade,
            profile text not null,
            cache text not null,
            query text not null,
            UNIQUE(crate, profile, cache, query)
        );
        create table self_profile_query(
            series integer references self_profile_query_series(id) on delete cascade on update cascade,
            aid integer references artifact(id) on delete cascade on update cascade,
            cid integer references collection(id) on delete cascade on update cascade,
            self_time integer,
            blocked_time integer,
            incremental_load_time integer,
            number_of_cache_hits integer,
            invocation_count integer,
            PRIMARY KEY(series, aid, cid)
        );
        create table pull_request_builds(
            bors_sha text unique,
            pr integer not null,
            parent_sha text,
            complete boolean,
            requested timestamp without time zone
        );
        "#,
    ),
    Migration::new(
        r#"
        create table artifact_collection_duration(
            aid integer primary key not null references artifact(id) on delete cascade on update cascade,
            date_recorded timestamp without time zone not null,
            duration integer not null
        );
        "#,
    ),
    Migration::new(
        r#"
        create table collector_progress(
            aid integer not null references artifact(id) on delete cascade on update cascade,
            step text not null,
            start integer,
            end integer,
            UNIQUE(aid, step)
        );
        "#,
    ),
    Migration::new("alter table collection add column perf_commit text"),
    Migration::new("alter table pull_request_builds add column include text"),
    Migration::new("alter table pull_request_builds add column exclude text"),
    Migration::new("alter table pull_request_builds add column runs integer"),
    Migration::new(
        r#"
        create table rustc_compilation(
            aid integer references artifact(id) on delete cascade on update cascade,
            cid integer references collection(id) on delete cascade on update cascade,
            crate text not null,
            duration integer not null,
            PRIMARY KEY(aid, cid, crate)
        );
        "#,
    ),
    Migration::new("alter table pull_request_builds rename to pull_request_build"),
    Migration::new(
        r#"
        create table raw_self_profile(
            aid integer references artifact(id) on delete cascade on update cascade,
            cid integer references collection(id) on delete cascade on update cascade,
            crate text not null references benchmark(name) on delete cascade on update cascade,
            profile text not null,
            cache text not null,
            PRIMARY KEY(aid, cid, crate, profile, cache)
        );
        "#,
    ),
    // Add not null constraint to benchmark name.
    Migration::without_foreign_key_constraints(
        r#"
        create table benchmark_new(
            name text primary key not null,
            stabilized bool not null
        );
        insert into benchmark_new select * from benchmark where name is not null;
        drop table benchmark;
        alter table benchmark_new rename to benchmark;
        "#,
    ),
    Migration::new("alter table benchmark add column category text not null default ''"),
];

#[async_trait::async_trait]
impl ConnectionManager for Sqlite {
    type Connection = Mutex<rusqlite::Connection>;
    async fn open(&self) -> Self::Connection {
        let mut conn = rusqlite::Connection::open(&self.0).unwrap();
        conn.pragma_update(None, "cache_size", &-128000).unwrap();
        conn.pragma_update(None, "journal_mode", &"WAL").unwrap();
        conn.pragma_update(None, "foreign_keys", &"ON").unwrap();

        self.1.call_once(|| {
            let version: i32 = conn
                .query_row(
                    "select user_version from pragma_user_version;",
                    params![],
                    |row| row.get(0),
                )
                .unwrap();
            for mid in (version as usize + 1)..MIGRATIONS.len() {
                MIGRATIONS[mid].execute(&mut conn, mid as i32);
            }
        });

        Mutex::new(conn)
    }
    async fn is_valid(&self, conn: &mut Self::Connection) -> bool {
        conn.get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .execute_batch("")
            .is_ok()
    }
}

pub struct SqliteConnection {
    conn: ManagedConnection<Mutex<rusqlite::Connection>>,
}

fn assert_sync<T: Sync>() {}

impl SqliteConnection {
    pub fn new(conn: ManagedConnection<Mutex<rusqlite::Connection>>) -> Self {
        assert_sync::<Self>();
        Self { conn }
    }

    pub fn raw(&mut self) -> &mut rusqlite::Connection {
        self.conn.get_mut().unwrap_or_else(|e| e.into_inner())
    }
    pub fn raw_ref(&self) -> std::sync::MutexGuard<rusqlite::Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl Connection for SqliteConnection {
    async fn maybe_create_indices(&mut self) {
        self.raw().execute_batch("
            create index if not exists pstat_on_series_aid on pstat(series, aid);
            create index if not exists self_profile_query_on_series_aid on self_profile_query(series, aid);
        ").unwrap();
    }

    async fn transaction(&mut self) -> Box<dyn Transaction + '_> {
        self.raw().execute_batch("BEGIN DEFERRED").unwrap();
        Box::new(SqliteTransaction {
            conn: self,
            finished: false,
        })
    }

    async fn record_duration(&self, artifact: ArtifactIdNumber, duration: Duration) {
        self.raw_ref()
            .prepare_cached(
                "insert or ignore into artifact_collection_duration (aid, date_recorded, duration) VALUES (?, strftime('%s','now'), ?)",
            )
            .unwrap()
            .execute(params![artifact.0, duration.as_secs() as i64])
            .unwrap();
    }

    async fn load_index(&mut self) -> Index {
        let commits = self
            .raw()
            .prepare(
                "select id, name, date, type from artifact where type = 'master' or type = 'try'",
            )
            .unwrap()
            .query_map(params![], |row| {
                Ok((
                    row.get::<_, i32>(0)? as u32,
                    Commit {
                        sha: row.get::<_, String>(1)?.as_str().into(),
                        date: {
                            let timestamp: Option<i64> = row.get(2)?;
                            match timestamp {
                                Some(t) => Date(Utc.timestamp(t, 0)),
                                None => Date(Utc.ymd(2001, 01, 01).and_hms(0, 0, 0)),
                            }
                        },
                        r#type: CommitType::from_str(&row.get::<_, String>(3)?).unwrap(),
                    },
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let artifacts = self
            .raw()
            .prepare("select id, name from artifact where type = 'release'")
            .unwrap()
            .query_map(params![], |row| {
                Ok((
                    row.get::<_, i32>(0)? as u32,
                    row.get::<_, String>(1)?.into_boxed_str(),
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let queries = self
            .raw()
            .prepare("select id, crate, profile, cache, query from self_profile_query_series;")
            .unwrap()
            .query_map(params![], |row| {
                Ok((
                    row.get::<_, i32>(0)? as u32,
                    (
                        Benchmark::from(row.get::<_, String>(1)?.as_str()),
                        match row.get::<_, String>(2)?.as_str() {
                            "check" => Profile::Check,
                            "opt" => Profile::Opt,
                            "debug" => Profile::Debug,
                            "doc" => Profile::Doc,
                            o => unreachable!("{}: not a profile", o),
                        },
                        row.get::<_, String>(3)?.as_str().parse().unwrap(),
                        row.get::<_, String>(4)?.as_str().into(),
                    ),
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let errors = self
            .raw()
            .prepare("select id, crate from error_series")
            .unwrap()
            .query_map(params![], |row| {
                Ok((
                    row.get::<_, i32>(0)? as u32,
                    row.get::<_, String>(1)?.as_str().into(),
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        Index {
            commits,
            artifacts,
            errors,
            pstat_series: self
                .raw()
                .prepare("select id, crate, profile, cache, statistic from pstat_series;")
                .unwrap()
                .query_map(params![], |row| {
                    Ok((
                        row.get::<_, i32>(0)? as u32,
                        (
                            Benchmark::from(row.get::<_, String>(1)?.as_str()),
                            match row.get::<_, String>(2)?.as_str() {
                                "check" => Profile::Check,
                                "opt" => Profile::Opt,
                                "debug" => Profile::Debug,
                                "doc" => Profile::Doc,
                                o => unreachable!("{}: not a profile", o),
                            },
                            row.get::<_, String>(3)?.as_str().parse().unwrap(),
                            row.get::<_, String>(4)?.as_str().into(),
                        ),
                    ))
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect(),
            queries,
        }
    }

    async fn get_benchmarks(&self) -> Vec<BenchmarkData> {
        let conn = self.raw_ref();
        let mut query = conn
            .prepare_cached("select name, category from benchmark")
            .unwrap();
        let rows = query
            .query_map([], |row| {
                Ok(BenchmarkData {
                    name: row.get(0)?,
                    category: row.get::<_, String>(1)?,
                })
            })
            .unwrap();
        let mut benchmarks = Vec::new();
        for row in rows {
            benchmarks.push(row.unwrap());
        }
        benchmarks
    }

    async fn get_pstats(
        &self,
        series: &[u32],
        artifact_row_ids: &[Option<ArtifactIdNumber>],
    ) -> Vec<Vec<Option<f64>>> {
        let conn = self.raw_ref();
        let mut query = conn
            .prepare_cached("select min(value) from pstat where series = ? and aid = ?;")
            .unwrap();
        series
            .iter()
            .map(|sid| {
                let elements = artifact_row_ids
                    .iter()
                    .map(|aid| {
                        aid.and_then(|aid| {
                            query
                                .query_row(params![&sid, &aid.0], |row| row.get(0))
                                .unwrap_or_else(|e| {
                                    panic!("{:?}: series={:?}, aid={:?}", e, sid, aid);
                                })
                        })
                    })
                    .collect::<Vec<_>>();
                if elements.is_empty() {
                    vec![None; artifact_row_ids.len()]
                } else {
                    elements
                }
            })
            .collect()
    }
    async fn get_self_profile_query(
        &self,
        series: u32,
        aid: ArtifactIdNumber,
    ) -> Option<QueryDatum> {
        self.raw_ref().prepare_cached("
                select self_time, blocked_time, incremental_load_time, number_of_cache_hits, invocation_count
                    from self_profile_query
                    where series = ? and aid = ? order by self_time asc;").unwrap()
            .query_row(params![&series, &aid.0], |row| {
        let self_time: i64 = row.get(0)?;
        let blocked_time: i64 = row.get(1)?;
        let incremental_load_time: i64 = row.get(2)?;
        Ok(QueryDatum {
            self_time: Duration::from_nanos(self_time as u64),
            blocked_time: Duration::from_nanos(blocked_time as u64),
            incremental_load_time: Duration::from_nanos(incremental_load_time as u64),
            number_of_cache_hits: row.get(3)?,
            invocation_count: row.get(4)?,
        })

            })
            .optional()
            .unwrap()
    }
    async fn get_self_profile(
        &self,
        aid: ArtifactIdNumber,
        crate_: &str,
        profile: &str,
        scenario: &str,
    ) -> HashMap<crate::QueryLabel, crate::QueryDatum> {
        self.raw_ref()
            .prepare_cached("
                select
                    query, self_time, blocked_time, incremental_load_time, number_of_cache_hits, invocation_count
                from self_profile_query_series
                join self_profile_query on self_profile_query_series.id = self_profile_query.series
                where
                    crate = ?
                    and profile = ?
                    and cache = ?
                    and aid = ?
                ")
            .unwrap()
            .query_map(params![&crate_, &profile, &scenario, &aid.0], |r| {
                let self_time: i64 = r.get(1)?;
                let blocked_time: i64 = r.get(2)?;
                let incremental_load_time: i64 = r.get(3)?;
                Ok((
                    r.get::<_, String>(0)?.as_str().into(),
                    crate::QueryDatum {
                        self_time: Duration::from_nanos(self_time as u64),
                        blocked_time: Duration::from_nanos(blocked_time as u64),
                        incremental_load_time: Duration::from_nanos(incremental_load_time as u64),
                        number_of_cache_hits: r.get::<_, i32>(4)? as u32,
                        invocation_count: r.get::<_, i32>(5)? as u32,
                    },
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
    async fn get_error(&self, aid: crate::ArtifactIdNumber) -> HashMap<String, String> {
        self.raw_ref()
            .prepare_cached(
                "select crate, error from error_series
                    inner join error on error.series = error_series.id and aid = ?",
            )
            .unwrap()
            .query_map(params![&aid.0], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
    async fn queue_pr(
        &self,
        pr: u32,
        include: Option<&str>,
        exclude: Option<&str>,
        runs: Option<i32>,
    ) {
        self.raw_ref()
            .prepare_cached(
                "insert into pull_request_build (pr, complete, requested, include, exclude, runs) VALUES (?, 0, strftime('%s','now'), ?, ?, ?)",
            )
            .unwrap()
            .execute(params![pr, include, exclude, &runs])
            .unwrap();
    }
    async fn pr_attach_commit(&self, pr: u32, sha: &str, parent_sha: &str) -> bool {
        self.raw_ref()
            .prepare_cached(
                "update pull_request_build SET bors_sha = ?, parent_sha = ?
                where pr = ? and bors_sha is null",
            )
            .unwrap()
            .execute(params![sha, parent_sha, pr])
            .unwrap()
            > 0
    }
    async fn queued_commits(&self) -> Vec<QueuedCommit> {
        self.raw_ref()
            .prepare_cached(
                "select pr, bors_sha, parent_sha, include, exclude, runs from pull_request_build
                where complete is false and bors_sha is not null
                order by requested asc",
            )
            .unwrap()
            .query(params![])
            .unwrap()
            .mapped(|row| {
                Ok(QueuedCommit {
                    pr: row.get(0).unwrap(),
                    sha: row.get(1).unwrap(),
                    parent_sha: row.get(2).unwrap(),
                    include: row.get(3).unwrap(),
                    exclude: row.get(4).unwrap(),
                    runs: row.get(5).unwrap(),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }
    async fn mark_complete(&self, sha: &str) -> Option<QueuedCommit> {
        let count = self
            .raw_ref()
            .execute(
                "update pull_request_build SET complete = 1 where sha = ? and complete = 0",
                params![sha],
            )
            .unwrap();
        if count == 0 {
            return None;
        }
        assert_eq!(count, 1, "sha is unique column");
        self.raw_ref()
            .query_row(
                "select pr, sha, parent_sha, include, exclude, runs from pull_request_build
            where sha = ?",
                params![sha],
                |row| {
                    Ok(QueuedCommit {
                        pr: row.get(0).unwrap(),
                        sha: row.get(1).unwrap(),
                        parent_sha: row.get(2).unwrap(),
                        include: row.get(3).unwrap(),
                        exclude: row.get(4).unwrap(),
                        runs: row.get(5).unwrap(),
                    })
                },
            )
            .optional()
            .unwrap()
    }
    async fn collection_id(&self, version: &str) -> CollectionId {
        let raw = self.raw_ref();
        raw.execute(
            "insert into collection (perf_commit) values (?)",
            params![version],
        )
        .unwrap();
        CollectionId(
            raw.query_row(
                "select id from collection where rowid = last_insert_rowid()",
                params![],
                |r| r.get(0),
            )
            .unwrap(),
        )
    }

    async fn record_statistic(
        &self,
        collection: CollectionId,
        artifact: ArtifactIdNumber,
        benchmark: &str,
        profile: Profile,
        scenario: crate::Scenario,
        metric: &str,
        value: f64,
    ) {
        let profile = profile.to_string();
        let scenario = scenario.to_string();
        self.raw_ref().execute("insert or ignore into pstat_series (crate, profile, cache, statistic) VALUES (?, ?, ?, ?)", params![
            &benchmark,
            &profile,
            &scenario,
            &metric,
        ]).unwrap();
        let sid: i32 = self.raw_ref().query_row("select id from pstat_series where crate = ? and profile = ? and cache = ? and statistic = ?", params![
            &benchmark,
            &profile,
            &scenario,
            &metric,
        ], |r| r.get(0)).unwrap();
        self.raw_ref()
            .execute(
                "insert into pstat (series, aid, cid, value) VALUES (?, ?, ?, ?)",
                params![&sid, &artifact.0, &collection.0, &value],
            )
            .unwrap();
    }

    async fn record_rustc_crate(
        &self,
        collection: CollectionId,
        artifact: ArtifactIdNumber,
        krate: &str,
        value: Duration,
    ) {
        self.raw_ref()
            .execute(
                "insert into rustc_compilation (aid, cid, crate, duration) VALUES (?, ?, ?, ?)",
                params![
                    &artifact.0,
                    &collection.0,
                    &krate,
                    &(value.as_nanos() as i64)
                ],
            )
            .unwrap();
    }

    async fn artifact_id(&self, artifact: &crate::ArtifactId) -> ArtifactIdNumber {
        let (name, date, ty) = match artifact {
            crate::ArtifactId::Commit(commit) => (
                commit.sha.to_string(),
                Some(commit.date.0),
                if commit.is_try() { "try" } else { "master" },
            ),
            crate::ArtifactId::Tag(a) => (a.clone(), None, "release"),
        };

        self.raw_ref()
            .execute(
                "insert or ignore into artifact (name, date, type) VALUES (?, ?, ?)",
                params![&name, &date.map(|d| d.timestamp()), &ty,],
            )
            .unwrap();
        ArtifactIdNumber(
            self.raw_ref()
                .query_row(
                    "select id from artifact where name = $1",
                    params![&name],
                    |r| r.get::<_, i32>(0),
                )
                .unwrap() as u32,
        )
    }

    async fn record_self_profile_query(
        &self,
        collection: CollectionId,
        artifact: ArtifactIdNumber,
        benchmark: &str,
        profile: Profile,
        scenario: crate::Scenario,
        query: &str,
        qd: QueryDatum,
    ) {
        let profile = profile.to_string();
        let scenario = scenario.to_string();
        self.raw_ref().execute("insert or ignore into self_profile_query_series (crate, profile, cache, query) VALUES (?, ?, ?, ?)", params![
            &benchmark,
            &profile,
            &scenario,
            &query,
        ]).unwrap();
        let sid: i32 = self.raw_ref().query_row("select id from self_profile_query_series where crate = ? and profile = ? and cache = ? and query = ?", params![
            &benchmark,
            &profile,
            &scenario,
            &query,
        ], |r| r.get(0)).unwrap();
        self.raw_ref()
            .prepare_cached(
                "insert into self_profile_query(
                    series,
                    aid,
                    cid,
                    self_time,
                    blocked_time,
                    incremental_load_time,
                    number_of_cache_hits,
                    invocation_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .unwrap()
            .execute(params![
                &sid,
                &artifact.0,
                &collection.0,
                &i64::try_from(qd.self_time.as_nanos()).unwrap(),
                &i64::try_from(qd.blocked_time.as_nanos()).unwrap(),
                &i64::try_from(qd.incremental_load_time.as_nanos()).unwrap(),
                qd.number_of_cache_hits,
                qd.invocation_count,
            ])
            .unwrap();
    }
    async fn record_error(&self, artifact: ArtifactIdNumber, krate: &str, error: &str) {
        self.raw_ref()
            .execute(
                "insert or ignore into error_series (crate) VALUES (?)",
                params![&krate,],
            )
            .unwrap();
        let sid: i32 = self
            .raw_ref()
            .query_row(
                "select id from error_series where crate = ?",
                params![&krate,],
                |r| r.get(0),
            )
            .unwrap();
        self.raw_ref()
            .execute(
                "insert into error (series, aid, error) VALUES (?, ?, ?)",
                params![&sid, &artifact.0, &error],
            )
            .unwrap();
    }
    async fn record_benchmark(
        &self,
        benchmark: &str,
        supports_stable: Option<bool>,
        category: String,
    ) {
        if let Some(stable) = supports_stable {
            self.raw_ref()
                .execute(
                    "insert into benchmark (name, stabilized, category) VALUES (?, ?, ?)
                ON CONFLICT (name) do update set stabilized = excluded.stabilized, category = excluded.category",
                    params![benchmark, stable, category],
                )
                .unwrap();
        } else {
            self.raw_ref()
                .execute(
                    "insert into benchmark (name, stabilized, category) VALUES (?, ?, ?)
                ON CONFLICT (name) do update set category = excluded.category",
                    params![benchmark, false, category],
                )
                .unwrap();
        }
    }
    async fn collector_start(&self, aid: ArtifactIdNumber, steps: &[String]) {
        // Clean out any leftover unterminated steps.
        self.raw_ref()
            .execute_batch("delete from collector_progress where start is null or end is null;")
            .unwrap();

        // Populate unstarted and unfinished steps into collector_progress.
        for step in steps {
            self.raw_ref()
                .execute(
                    "insert or ignore into collector_progress(aid, step) VALUES (?, ?)",
                    params![&aid.0, step],
                )
                .unwrap();
        }
    }
    async fn collector_start_step(&self, aid: ArtifactIdNumber, step: &str) -> bool {
        self.raw_ref()
            .execute(
                "update collector_progress set start = strftime('%s','now') \
                where aid = ? and step = ? and end is null;",
                params![&aid.0, &step],
            )
            .unwrap()
            == 1
    }
    async fn collector_end_step(&self, aid: ArtifactIdNumber, step: &str) {
        let did_modify = self
            .raw_ref()
            .execute(
                "update collector_progress set end = strftime('%s','now') \
                where aid = ? and step = ? and start is not null and end is null;",
                params![&aid.0, &step],
            )
            .unwrap()
            == 1;
        if !did_modify {
            log::error!("did not end {} for {:?}", step, aid);
        }
    }
    async fn in_progress_artifacts(&self) -> Vec<ArtifactId> {
        let conn = self.raw_ref();
        let mut aids = conn
            .prepare(
                "select distinct aid from collector_progress \
                where end is null order by aid limit 1",
            )
            .unwrap();

        let aids = aids.query_map(params![], |r| r.get::<_, i32>(0)).unwrap();

        let mut artifacts = Vec::new();
        for aid in aids {
            let aid = aid.unwrap();
            let (name, date, ty) = conn
                .query_row(
                    "select name, date, type from artifact where id = ?",
                    params![&aid],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Option<i64>>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )
                .unwrap();

            artifacts.push(match ty.as_str() {
                "try" | "master" => ArtifactId::Commit(Commit {
                    sha: name,
                    date: date
                        .map(|d| Utc.timestamp(d, 0))
                        .map(Date)
                        .unwrap_or_else(|| Date::ymd_hms(2001, 01, 01, 0, 0, 0)),
                    r#type: CommitType::from_str(&ty).unwrap(),
                }),
                "release" => ArtifactId::Tag(name),
                _ => {
                    log::error!("unknown ty {:?}", ty);
                    continue;
                }
            });
        }
        artifacts
    }
    async fn in_progress_steps(&self, artifact: &ArtifactId) -> Vec<crate::Step> {
        let aid = self.artifact_id(artifact).await;

        self.raw_ref()
            .prepare(
                "
                select
                    step,
                    end_time is not null,
                    coalesce(end, strftime('%s', 'now')) - start,
                    (select end - start
                        from collector_progress as cp
                            where
                                cp.step = collector_progress.step
                                and cp.start is not null
                                and cp.end is not null
                            limit 1
                    )
                from collector_progress where aid = ? order by step
            ",
            )
            .unwrap()
            .query_map(params![&aid.0], |row| {
                Ok(crate::Step {
                    name: row.get(0)?,
                    is_done: row.get(1)?,
                    duration: Duration::from_secs(row.get::<_, i64>(2)? as u64),
                    expected: Duration::from_secs(row.get::<_, i64>(3)? as u64),
                })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }
    async fn last_end_time(&self) -> Option<DateTime<Utc>> {
        self.raw_ref()
            .query_row(
                "select date_recorded + duration \
                from artifact_collection_duration \
                order by date_recorded desc \
                limit 1;",
                params![],
                |r| Ok(Utc.timestamp(r.get(0)?, 0)),
            )
            .optional()
            .unwrap()
    }
    async fn parent_of(&self, sha: &str) -> Option<String> {
        let mut shas = self
            .raw_ref()
            .prepare_cached("select parent_sha from pull_request_build where bors_sha = ?")
            .unwrap()
            .query(params![sha])
            .unwrap()
            .mapped(|row| Ok(row.get(0).unwrap()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        shas.pop()
    }

    async fn pr_of(&self, sha: &str) -> Option<u32> {
        self.raw_ref()
            .query_row(
                "select pr from pull_request_build where bors_sha = ?",
                params![sha],
                |row| Ok(row.get(0).unwrap()),
            )
            .optional()
            .unwrap()
    }
    async fn record_raw_self_profile(
        &self,
        _collection: CollectionId,
        _artifact: ArtifactIdNumber,
        _benchmark: &str,
        _profile: Profile,
        _scenario: crate::Scenario,
    ) {
        // FIXME: this is left for the future, if we ever need to support it. It
        // shouldn't be too hard, but we may also want to just intern the raw
        // self profile files into sqlite database or something like that, not
        // yet clear.
        unimplemented!("recording raw self profile files is not implemented for sqlite")
    }
    async fn list_self_profile(
        &self,
        aid: ArtifactId,
        crate_: &str,
        profile: &str,
        scenario: &str,
    ) -> Vec<(ArtifactIdNumber, i32)> {
        self.raw_ref()
            .prepare(
                "select aid, cid from raw_self_profile where
        crate = ?1 and
        profile = ?2 and
        cache = ?3 and
        aid = (select id from artifact where name = ?4);",
            )
            .unwrap()
            .query_map(
                params![
                    &crate_,
                    profile,
                    scenario,
                    &match aid {
                        ArtifactId::Commit(c) => c.sha,
                        ArtifactId::Tag(a) => a,
                    }
                ],
                |r| Ok((ArtifactIdNumber(r.get::<_, i32>(0)? as u32), r.get(1)?)),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    async fn get_bootstrap(&self, aids: &[ArtifactIdNumber]) -> Vec<Option<Duration>> {
        aids.into_iter()
            .map(|aid| {
                self.raw_ref()
                    .prepare(
                        "
                        select min(total)
                        from (
                            select sum(duration) as total
                            from rustc_compilation
                            where aid = ?
                            group by cid
                        )
                    ",
                    )
                    .unwrap()
                    .query_row(params![&aid.0], |row| {
                        Ok(Duration::from_nanos(row.get::<_, i64>(0)? as u64))
                    })
                    .optional()
                    .unwrap()
            })
            .collect()
    }

    async fn get_bootstrap_by_crate(
        &self,
        aids: &[ArtifactIdNumber],
    ) -> HashMap<String, Vec<Option<Duration>>> {
        let mut results = HashMap::new();

        for (idx, aid) in aids.iter().copied().enumerate() {
            let rows: Vec<(String, i64)> = self
                .raw_ref()
                .prepare("select crate, min(duration) from rustc_compilation where aid = ? group by crate")
                .unwrap()
                .query_map(params![&aid.0], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            for (krate, min_duration) in rows {
                let v = results
                    .entry(krate)
                    .or_insert_with(|| vec![None; aids.len()]);
                v[idx] = Some(Duration::from_nanos(min_duration as u64));
            }
        }

        results
    }

    async fn artifact_by_name(&self, artifact: &str) -> Option<ArtifactId> {
        let (date, ty) = self
            .raw_ref()
            .prepare("select date, type from artifact where name = ?")
            .unwrap()
            .query_row(params![&artifact], |r| {
                let date = r.get::<_, Option<i64>>(0)?;
                let ty = r.get::<_, String>(1)?;
                Ok((date, ty))
            })
            .optional()
            .unwrap()?;

        match ty.as_str() {
            "master" => Some(ArtifactId::Commit(Commit {
                sha: artifact.to_owned(),
                date: Date(Utc.timestamp(date.expect("master has date"), 0)),
                r#type: CommitType::Master,
            })),
            "try" => Some(ArtifactId::Commit(Commit {
                sha: artifact.to_owned(),
                date: Date::ymd_hms(2000, 1, 1, 0, 0, 0),
                r#type: CommitType::Try,
            })),
            "release" => Some(ArtifactId::Tag(artifact.to_owned())),
            _ => panic!("unknown artifact type: {:?}", ty),
        }
    }
}
