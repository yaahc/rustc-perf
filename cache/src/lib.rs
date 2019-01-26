use anymap::Map;
use std::cell::RefCell;
use std::hash::Hash;
use thread_local::CachedThreadLocal;

mod writeset;

use writeset::WriteSet;

type AnyMap = Map<anymap::any::Any + Send>;

lazy_static::lazy_static! {
    static ref CACHE: Cache = Cache::new();
}

struct Cache {
    map: CachedThreadLocal<RefCell<AnyMap>>,
}

impl Cache {
    fn new() -> Cache {
        let c = Cache {
            map: CachedThreadLocal::new(),
        };
        // initialize
        let _ = c.map.get_or(|| Box::new(RefCell::new(AnyMap::new())));
        c
    }

    fn map(&self) -> &RefCell<AnyMap> {
        self.map.get().unwrap()
    }

    /// Inserts, if needed, and returns
    fn get<T: Sync + Send + Hash + Eq + 'static>(&self, v: T) -> &'static T {
        let mut map = self.map().borrow_mut();
        if map.get::<WriteSet<T>>().is_none() {
            map.insert(WriteSet::<T>::new());
        }
        let set = map.get::<WriteSet<T>>().unwrap();
        set.get(v)
    }
}

pub fn cache<T: Sync + Send + Hash + Eq + 'static>(v: T) -> &'static T {
    CACHE.get(v)
}
