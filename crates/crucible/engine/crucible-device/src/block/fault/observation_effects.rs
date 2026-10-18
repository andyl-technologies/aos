//! Private accounting at retained storage mutation and external effect sites.
//!
//! The outer entry reserves its revision before effects. These helpers record
//! actual affected fields, map entries and vectors without copying unrelated
//! retained payloads. Staged owner clones carry the markers into a commit;
//! discarding a staged transaction discards its markers too. None grants Source
//! or payload-effect authority.

macro_rules! observed_set {
    ($owner:ident, $field:ident, $value:expr) => {{
        let value = $value;
        if $owner.$field != value {
            $owner.observation_changed = true;
            $owner.$field = value;
        }
    }};
}

macro_rules! observed_insert {
    ($owner:ident, $field:ident, $value:expr $(,)?) => {{
        let inserted = $owner.$field.insert($value);
        $owner.observation_changed |= inserted;
        inserted
    }};
    ($owner:ident, $field:ident, $key:expr, $value:expr $(,)?) => {{
        let key = $key;
        let value = $value;
        if $owner.$field.get(&key) != Some(&value) {
            $owner.observation_changed = true;
        }
        $owner.$field.insert(key, value)
    }};
}

macro_rules! observed_remove {
    ($owner:ident, retry_preserve_authorizations, $key:expr $(,)?) => {{
        let removed = $owner.retry_preserve_authorizations.remove($key);
        $owner.observation_changed |= removed;
        removed
    }};
    ($owner:ident, $field:ident, $key:expr $(,)?) => {{
        let key = $key;
        if $owner.$field.contains_key(key) {
            $owner.observation_changed = true;
        }
        $owner.$field.remove(key)
    }};
}

macro_rules! observed_push {
    ($owner:ident, $field:ident, $value:expr $(,)?) => {{
        let value = $value;
        $owner.observation_changed = true;
        $owner.$field.push(value)
    }};
}

macro_rules! observed_clear {
    ($owner:ident, $field:ident $(,)?) => {{
        if !$owner.$field.is_empty() {
            $owner.observation_changed = true;
            $owner.$field.clear();
        }
    }};
}

macro_rules! observed_retain {
    ($owner:ident, $field:ident, $predicate:expr $(,)?) => {{
        let before = $owner.$field.len();
        $owner.$field.retain($predicate);
        $owner.observation_changed |= $owner.$field.len() != before;
    }};
}

macro_rules! observed_member_set {
    ($owner:ident, $member:expr, $value:expr $(,)?) => {{
        let value = $value;
        if $member != value {
            $owner.observation_changed = true;
            $member = value;
        }
    }};
}

macro_rules! observed_take {
    ($owner:ident, $field:ident $(,)?) => {{
        if !$owner.$field.is_empty() {
            $owner.observation_changed = true;
        }
        std::mem::take(&mut $owner.$field)
    }};
}

macro_rules! observed_drain {
    ($owner:ident, $effect:expr) => {{
        let drained = $effect;
        $owner.observation_changed |= !drained.is_empty();
        drained
    }};
}
