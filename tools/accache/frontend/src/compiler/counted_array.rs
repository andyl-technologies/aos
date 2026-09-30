// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Adapted from sccache 8396f0209d74d496b7cb27cdf323cd3ff8d4a291.

/// Helper macro to create fixed-length arrays without specifying a fixed size
#[macro_export]
macro_rules! counted_array {
    ($v:vis static $name:ident : [ $t:ty ; _ ] = [$($value:expr),* $(,)?] ) => {
        $v static $name : [
            $t;
            counted_array!(@count $($value,)*)
        ] = [
            $( $value ),*
        ];
    };
    // The best way to count variadic args
    // according to <https://github.com/rust-lang/lang-team/issues/28>
    (@count ) => { 0usize };
    (@count $($arg:expr,)*) => {
        <[()]>::len(&[ $( counted_array!( @nil $arg ), )*])
    };

    (@nil $orig:expr) => {
        ()
    };
}

#[cfg(test)]
mod test {
    #[test]
    fn counted_array_macro() {
        counted_array!(static ARR_QUAD: [u8;_] = [1,2,3,4,]);
        assert_eq!(ARR_QUAD.len(), 4);
    }
}
