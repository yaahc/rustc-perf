use std::cell::RefCell;
use std::collections::HashSet;
use std::hash::Hash;

pub struct WriteSet<T: 'static> {
    set: RefCell<HashSet<&'static T>>,
}

impl<T: Send + Sync + Hash + Eq> WriteSet<T> {
    pub fn new() -> Self {
        WriteSet {
            set: RefCell::new(HashSet::new()),
        }
    }

    pub fn get(&self, v: T) -> &'static T {
        let mut set = self.set.borrow_mut();
        if let Some(v) = set.get(&v) {
            v
        } else {
            let v = &*Box::leak(Box::new(v));

            set.insert(v);

            v
        }
    }
}
