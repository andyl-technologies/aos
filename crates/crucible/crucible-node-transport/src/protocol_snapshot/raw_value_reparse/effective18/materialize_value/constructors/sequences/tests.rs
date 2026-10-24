//! Exercises the actual selected constructor families through ordinary Cargo.

use super::*;

// These controls mirror only the parent's observed-capacity refusal boundary.
// try_reserve_exact is not used as a generic promise of exact returned capacity.
// Both successful and refused allocations stay in the caller's real bank.
fn reserve_bank<T>(
    bank: &mut Vec<T>,
    count: usize,
    requested_backing: usize,
    observed_backing: &mut Option<usize>,
) -> Result<(), ProviderError> {
    bank.try_reserve_exact(count).map_err(|_| failure())?;
    let actual = bank
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or_else(failure)?;
    *observed_backing = Some(actual);
    if actual > requested_backing {
        return Err(failure());
    }
    Ok(())
}

fn reserve_string(
    text: &mut String,
    count: usize,
    requested_backing: usize,
    observed_backing: &mut Option<usize>,
) -> Result<(), ProviderError> {
    text.try_reserve_exact(count).map_err(|_| failure())?;
    *observed_backing = Some(text.capacity());
    if text.capacity() > requested_backing {
        return Err(failure());
    }
    Ok(())
}

fn typed_bank<T: 'static>(value: T) {
    let row = vec_reservation_data::<T>(1, usize::MAX).unwrap();
    let moves = vec_push_pop_data::<T>(1, 1, usize::MAX).unwrap();
    let drop_row = vec_shell_drop_data::<T>(usize::MAX).unwrap();
    let mut bank = Vec::new();
    let mut observed = None;
    let result = reserve_bank(&mut bank, 1, row[0], &mut observed);
    assert_eq!(observed, Some(bank.capacity() * size_of::<T>()));
    if result.is_err() {
        assert!(bank.is_empty());
        drop(bank);
        drop(value);
        return;
    }
    result.unwrap();

    assert!(observed.unwrap() <= row[0]);
    assert!(moves[1] > 0 && drop_row[2] > 0);
    assert!(bank.len() < bank.capacity());
    bank.push(value);
    let moved = bank.pop();
    assert!(moved.is_some());
    assert!(bank.is_empty());
    drop(bank);
    drop(moved);
}

#[test]
fn actual_work_frame_and_value_banks_reserve_once_then_move_without_growth() {
    typed_bank(Work::Finish { frame: 0 });
    typed_bank(BuildFrame {
        destination: Destination::Root,
        container: Container::Array(Vec::new()),
    });
    typed_bank(Value::Null);
}

#[test]
fn actual_empty_string_reserve_then_push_str_keeps_exact_utf8_bytes() {
    for text in ["", "ascii", "é😀\n\u{0000}"] {
        let row = string_copy_data(text.len(), usize::MAX).unwrap();
        let mut output = String::new();
        let mut observed = None;
        let result = reserve_string(&mut output, text.len(), row[0], &mut observed);
        assert_eq!(observed, Some(output.capacity()));
        if result.is_err() {
            assert!(output.is_empty());
            drop(output);
            continue;
        }
        result.unwrap();
        assert!(observed.unwrap() <= row[0]);
        output.push_str(text);

        assert_eq!(output, text);
        let drop_row = string_drop_data(usize::MAX).unwrap();
        assert_eq!(drop_row[0], 0);
        drop(output);
    }
}

#[test]
fn actual_ordinary_iterator_moves_array_elements_into_pre_reserved_retirement() {
    let array_row = vec_reservation_data::<Value>(3, usize::MAX).unwrap();
    let retire_row = vec_reservation_data::<Value>(3, usize::MAX).unwrap();
    let iterator_row = vec_into_iter_data::<Value>(3, usize::MAX).unwrap();
    let mut array = Vec::new();
    let mut retirement = Vec::new();
    let mut array_observed = None;
    let mut retirement_observed = None;
    let array_result = reserve_bank(&mut array, 3, array_row[0], &mut array_observed);
    let retirement_result =
        reserve_bank(&mut retirement, 3, retire_row[0], &mut retirement_observed);
    assert_eq!(array_observed, Some(array.capacity() * size_of::<Value>()));
    assert_eq!(
        retirement_observed,
        Some(retirement.capacity() * size_of::<Value>())
    );
    if array_result.is_err() || retirement_result.is_err() {
        assert!(array.is_empty() && retirement.is_empty());
        return;
    }
    array_result.unwrap();
    retirement_result.unwrap();
    for _ in 0..3 {
        array.push(Value::Null);
    }
    assert!(array.capacity() * size_of::<Value>() <= array_row[0]);
    assert!(retirement.capacity() * size_of::<Value>() <= retire_row[0]);

    for child in array {
        assert!(retirement.len() < retirement.capacity());
        retirement.push(child);
    }
    assert_eq!(retirement.len(), 3);
    assert_eq!(iterator_row[0], 0);
    while let Some(value) = retirement.pop() {
        assert!(matches!(value, Value::Null));
    }
    assert!(retirement.is_empty());
}

#[test]
fn actual_one_short_quote_stops_before_empty_bank_or_string_reserve() {
    let row = vec_reservation_data::<Value>(2, usize::MAX).unwrap();
    let maximum = row[0]
        .checked_add(row[1])
        .unwrap()
        .checked_add(row[2])
        .unwrap();
    let mut bank: Vec<Value> = Vec::new();
    let refusal = (|| -> Result<(), ProviderError> {
        vec_reservation_data::<Value>(2, maximum - 1)?;
        bank.try_reserve_exact(2).map_err(|_| failure())?;
        Ok(())
    })();
    assert!(refusal.is_err());
    assert_eq!(bank.capacity(), 0);

    let row = string_copy_data(7, usize::MAX).unwrap();
    let maximum = row[0]
        .checked_add(row[1])
        .unwrap()
        .checked_add(row[2])
        .unwrap();
    let mut text = String::new();
    let refusal = (|| -> Result<(), ProviderError> {
        string_copy_data(7, maximum - 1)?;
        text.try_reserve_exact(7).map_err(|_| failure())?;
        text.push_str("literal");
        Ok(())
    })();
    assert!(refusal.is_err());
    assert_eq!(text.capacity(), 0);
    assert!(text.is_empty());
}

#[test]
fn actual_empty_and_overflowing_requests_preserve_untouched_banks() {
    let row = vec_reservation_data::<Value>(0, usize::MAX).unwrap();
    let mut empty: Vec<Value> = Vec::new();
    empty.try_reserve_exact(0).unwrap();
    assert_eq!(row[0], 0);
    assert_eq!(empty.capacity(), 0);
    assert!(vec_reservation_data::<Value>(usize::MAX, usize::MAX).is_err());
    assert!(vec_push_pop_data::<Value>(usize::MAX, 1, usize::MAX).is_err());
    assert_eq!(empty.capacity(), 0);
}

#[test]
fn actual_typed_frame_and_array_slot_access_uses_bounded_usize_paths() {
    let mut frames = Vec::new();
    let requested = vec_reservation_data::<BuildFrame>(1, usize::MAX).unwrap();
    let mut observed = None;
    let result = reserve_bank(&mut frames, 1, requested[0], &mut observed);
    assert_eq!(observed, Some(frames.capacity() * size_of::<BuildFrame>()));
    if result.is_err() {
        assert!(frames.is_empty());
        return;
    }
    result.unwrap();
    frames.push(BuildFrame {
        destination: Destination::Root,
        container: Container::Array(Vec::new()),
    });
    vec_access_data::<BuildFrame>(usize::MAX).unwrap();
    assert!(frames.get(0).is_some());
    assert!(frames.get_mut(0).is_some());
    assert!(matches!(&frames[0].container, Container::Array(_)));
    frames[0].destination = Destination::Root;

    let mut values = Vec::new();
    let requested = vec_reservation_data::<Value>(1, usize::MAX).unwrap();
    let mut observed = None;
    let result = reserve_bank(&mut values, 1, requested[0], &mut observed);
    assert_eq!(observed, Some(values.capacity() * size_of::<Value>()));
    if result.is_err() {
        assert!(values.is_empty());
        return;
    }
    result.unwrap();
    values.push(Value::Null);
    vec_access_data::<Value>(usize::MAX).unwrap();
    assert!(values.get(0).is_some());
    let selected = values.get_mut(0).unwrap();
    assert!(matches!(selected, Value::Null));
    values[0] = Value::Bool(true);
    assert!(matches!(&values[0], Value::Bool(true)));
}
