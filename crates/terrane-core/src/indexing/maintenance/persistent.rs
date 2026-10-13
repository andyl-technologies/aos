//! Shares balanced immutable search paths between maintenance snapshots.

use alloc::rc::Rc;
use core::cmp::Ordering;

use super::accounting::MapWork;

type Link<K, V> = Option<Rc<Node<K, V>>>;

#[derive(Clone, Debug)]
struct Node<K, V> {
    key: K,
    value: V,
    left: Link<K, V>,
    right: Link<K, V>,
    height: usize,
    count: usize,
}

/// An AVL map whose snapshot clone shares its complete immutable root.
#[derive(Clone, Debug)]
pub(super) struct Map<K, V>(Link<K, V>);

impl<K, V> Default for Map<K, V> {
    fn default() -> Self {
        Self(None)
    }
}

fn height<K, V>(link: &Link<K, V>) -> usize {
    link.as_ref().map_or(0, |node| node.height)
}

fn count<K, V>(link: &Link<K, V>) -> usize {
    link.as_ref().map_or(0, |node| node.count)
}

fn node<K, V>(
    key: K,
    value: V,
    left: Link<K, V>,
    right: Link<K, V>,
    work: &mut MapWork,
) -> Rc<Node<K, V>> {
    work.allocate();
    Rc::new(Node {
        key,
        value,
        height: 1 + height(&left).max(height(&right)),
        count: 1 + count(&left) + count(&right),
        left,
        right,
    })
}

fn balance<K: Clone, V: Clone>(
    key: K,
    value: V,
    left: Link<K, V>,
    right: Link<K, V>,
    work: &mut MapWork,
) -> Rc<Node<K, V>> {
    if height(&left) > height(&right) + 1 {
        if let Some(child) = &left {
            if height(&child.left) >= height(&child.right) {
                let right = node(key, value, child.right.clone(), right, work);
                return node(
                    child.key.clone(),
                    child.value.clone(),
                    child.left.clone(),
                    Some(right),
                    work,
                );
            }
            if let Some(middle) = &child.right {
                let left = node(
                    child.key.clone(),
                    child.value.clone(),
                    child.left.clone(),
                    middle.left.clone(),
                    work,
                );
                let right = node(key, value, middle.right.clone(), right, work);
                return node(
                    middle.key.clone(),
                    middle.value.clone(),
                    Some(left),
                    Some(right),
                    work,
                );
            }
        }
    } else if height(&right) > height(&left) + 1
        && let Some(child) = &right
    {
        if height(&child.right) >= height(&child.left) {
            let left = node(key, value, left, child.left.clone(), work);
            return node(
                child.key.clone(),
                child.value.clone(),
                Some(left),
                child.right.clone(),
                work,
            );
        }
        if let Some(middle) = &child.left {
            let left = node(key, value, left, middle.left.clone(), work);
            let right = node(
                child.key.clone(),
                child.value.clone(),
                middle.right.clone(),
                child.right.clone(),
                work,
            );
            return node(
                middle.key.clone(),
                middle.value.clone(),
                Some(left),
                Some(right),
                work,
            );
        }
    }
    node(key, value, left, right, work)
}

fn insert<K: Ord + Clone, V: Clone>(
    link: &Link<K, V>,
    key: K,
    value: V,
    work: &mut MapWork,
) -> Rc<Node<K, V>> {
    let Some(current) = link else {
        return node(key, value, None, None, work);
    };
    work.probe();
    work.compare();
    match key.cmp(&current.key) {
        Ordering::Less => balance(
            current.key.clone(),
            current.value.clone(),
            Some(insert(&current.left, key, value, work)),
            current.right.clone(),
            work,
        ),
        Ordering::Greater => balance(
            current.key.clone(),
            current.value.clone(),
            current.left.clone(),
            Some(insert(&current.right, key, value, work)),
            work,
        ),
        Ordering::Equal => node(
            key,
            value,
            current.left.clone(),
            current.right.clone(),
            work,
        ),
    }
}

fn take_first<K: Clone, V: Clone>(
    current: &Rc<Node<K, V>>,
    work: &mut MapWork,
) -> (K, V, Link<K, V>) {
    work.probe();
    match &current.left {
        None => (
            current.key.clone(),
            current.value.clone(),
            current.right.clone(),
        ),
        Some(left) => {
            let (key, value, replacement) = take_first(left, work);
            let root = balance(
                current.key.clone(),
                current.value.clone(),
                replacement,
                current.right.clone(),
                work,
            );
            (key, value, Some(root))
        }
    }
}

fn remove<K: Ord + Clone, V: Clone>(link: &Link<K, V>, key: &K, work: &mut MapWork) -> Link<K, V> {
    let current = link.as_ref()?;
    work.probe();
    work.compare();
    match key.cmp(&current.key) {
        Ordering::Less => Some(balance(
            current.key.clone(),
            current.value.clone(),
            remove(&current.left, key, work),
            current.right.clone(),
            work,
        )),
        Ordering::Greater => Some(balance(
            current.key.clone(),
            current.value.clone(),
            current.left.clone(),
            remove(&current.right, key, work),
            work,
        )),
        Ordering::Equal => match &current.right {
            None => current.left.clone(),
            Some(right) => {
                let (key, value, right) = take_first(right, work);
                Some(balance(key, value, current.left.clone(), right, work))
            }
        },
    }
}

impl<K: Ord + Clone, V: Clone> Map<K, V> {
    /// Borrows the value for a key and records the lookup's search work.
    pub(super) fn get(&self, key: &K, work: &mut MapWork) -> Option<&V> {
        work.operation(self.height());
        let mut next = self.0.as_ref();
        while let Some(current) = next {
            work.probe();
            work.compare();
            match key.cmp(&current.key) {
                Ordering::Less => next = current.left.as_ref(),
                Ordering::Greater => next = current.right.as_ref(),
                Ordering::Equal => return Some(&current.value),
            }
        }
        None
    }

    /// Inserts or replaces a value by copying its balanced path and recording work.
    pub(super) fn insert(&mut self, key: K, value: V, work: &mut MapWork) {
        work.operation(self.height());
        self.0 = Some(insert(&self.0, key, value, work));
    }

    /// Removes a key if present, preserving other snapshots and recording work.
    pub(super) fn remove(&mut self, key: &K, work: &mut MapWork) {
        work.operation(self.height());
        self.0 = remove(&self.0, key, work);
    }

    /// Returns the number of stored key/value pairs.
    pub(super) fn len(&self) -> usize {
        count(&self.0)
    }

    /// Returns the root's stored height, or zero for an empty map.
    pub(super) fn height(&self) -> usize {
        height(&self.0)
    }

    /// Visits every key/value pair in ascending key order.
    ///
    /// # Panics
    /// Propagates any panic from the visitor.
    pub(super) fn visit(&self, visitor: &mut impl FnMut(&K, &V)) {
        fn walk<K, V>(link: &Link<K, V>, visitor: &mut impl FnMut(&K, &V)) {
            if let Some(node) = link {
                walk(&node.left, visitor);
                visitor(&node.key, &node.value);
                walk(&node.right, visitor);
            }
        }
        walk(&self.0, visitor);
    }

    #[cfg(test)]
    /// Checks subtree balance, stored metadata and immediate-child key order.
    ///
    /// # Panics
    /// Panics if subtree heights differ by more than one, stored heights or
    /// counts disagree with their children, or a child violates key order.
    pub(super) fn assert_balanced(&self) {
        fn check<K: Ord, V>(link: &Link<K, V>) -> (usize, usize) {
            let Some(node) = link else {
                return (0, 0);
            };
            let (left_height, left_count) = check(&node.left);
            let (right_height, right_count) = check(&node.right);
            assert!(left_height.abs_diff(right_height) <= 1);
            assert_eq!(node.height, 1 + left_height.max(right_height));
            assert_eq!(node.count, 1 + left_count + right_count);
            if let Some(left) = &node.left {
                assert!(left.key < node.key);
            }
            if let Some(right) = &node.right {
                assert!(right.key > node.key);
            }
            (node.height, node.count)
        }
        check(&self.0);
    }
}
