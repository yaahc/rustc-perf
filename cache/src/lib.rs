use anymap::Map;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Mutex;

mod writeset;

use writeset::WriteSet;

type AnyMap = Map<anymap::any::Any + Send>;

lazy_static::lazy_static! {
    static ref CACHE: Cache = Cache::new();
}

struct Cache {
    map: Mutex<AnyMap>,
}

impl Cache {
    fn new() -> Cache {
        Cache {
            map: Mutex::new(AnyMap::new()),
        }
    }

    /// Inserts, if needed, and returns
    fn get<T: Sync + Send + Hash + Eq + 'static>(&self, v: T) -> &'static T {
        let mut map = self.map.lock().expect("acquire lock");
        if map.get::<WriteSet<T>>().is_none() {
            map.insert(WriteSet::<T>::new());
        }
        let set = map.get::<WriteSet<T>>().unwrap();
        set.get(v)
    }
}

pub struct Cached<T: 'static>(&'static T);

impl<T> Cached<T> {
    pub fn take(self) -> T
    where
        T: Clone,
    {
        self.0.clone()
    }
}

impl<T> Copy for Cached<T> {}
impl<T> Clone for Cached<T> {
    fn clone(&self) -> Cached<T> {
        *self
    }
}

impl<T, U: ?Sized> PartialOrd<U> for Cached<T>
where
    U: PartialOrd<T>,
{
    fn partial_cmp(&self, other: &U) -> Option<Ordering> {
        other.partial_cmp(&self.0)
    }
}

impl<T: Eq> Eq for Cached<T> {}

impl<T> Ord for Cached<T>
where
    T: Eq + Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.cmp(&self.0)
    }
}

impl<T, U: ?Sized> PartialEq<U> for Cached<T>
where
    U: PartialEq<T>,
{
    fn eq(&self, other: &U) -> bool {
        other == self.0
    }
}

impl<T, U> AsRef<U> for Cached<T>
where
    T: AsRef<U>,
    U: ?Sized,
{
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<T: Sync + Send + Hash + Eq + 'static> Cached<T> {
    fn new(v: T) -> Self {
        Cached(CACHE.get(v))
    }
}

impl<T: Sync + Send + Hash + Eq + 'static> From<T> for Cached<T> {
    fn from(v: T) -> Cached<T> {
        Cached::new(v)
    }
}

impl<T> Deref for Cached<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0
    }
}

use std::borrow::Borrow;

impl Borrow<str> for Cached<String> {
    fn borrow(&self) -> &str {
        self.0.as_str()
    }
}

impl<T> Hash for Cached<T> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        Hash::hash(&(self.0 as *const T), state)
    }
}

impl<T: fmt::Debug> fmt::Debug for Cached<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<T: fmt::Display> fmt::Display for Cached<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de, T> Deserialize<'de> for Cached<T>
where
    T: Deserialize<'de> + Hash + Eq + Sync + Send + 'static,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = T::deserialize(deserializer)?;
        Ok(Cached::new(v))
    }
}

impl<T> Serialize for Cached<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        T::serialize(&self.0, serializer)
    }
}
