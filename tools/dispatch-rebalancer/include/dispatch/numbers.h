#pragma once

#include "dispatch/backend.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>

namespace dispatch::backend {

using Integer = boost::multiprecision::cpp_int;

inline Integer absolute(Integer value) {
  return value < 0 ? -value : value;
}

inline Integer gcd(Integer left, Integer right) {
  left = absolute(left);
  right = absolute(right);
  while (right != 0) {
    Integer remainder = left % right;
    left = right;
    right = remainder;
  }
  return left;
}

inline Integer decimal(const Json& value, bool signed_value = false) {
  if (!value.is_string()) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "numeric input must be a decimal string");
  }
  const auto text = value.get<std::string>();
  const std::size_t start = signed_value && text.starts_with('-') ? 1 : 0;
  if (text.size() == start || text.size() > 128 ||
      (text[start] == '0' && text.size() != start + 1)) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "noncanonical or oversized decimal input");
  }
  Integer result = 0;
  for (std::size_t index = start; index < text.size(); ++index) {
    if (text[index] < '0' || text[index] > '9') {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "invalid decimal input");
    }
    result = result * 10 + (text[index] - '0');
  }
  if (start != 0) {
    if (result == 0) {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "negative zero is noncanonical");
    }
    result = -result;
  }
  return result;
}

inline double exact_double(const Integer& value) {
  if (absolute(value) > kMaximumExactInteger) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL,
                "compiled integer exceeds the backend's exact binary64 range");
  }
  return value.convert_to<double>();
}

struct Rational {
  Integer numerator = 0;
  Integer denominator = 1;

  Rational() = default;
  Rational(Integer value) : numerator(std::move(value)) {}
  Rational(Integer num, Integer den) : numerator(std::move(num)), denominator(std::move(den)) {
    if (denominator <= 0) {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "rational denominator must be positive");
    }
    const Integer divisor = gcd(numerator, denominator);
    numerator /= divisor;
    denominator /= divisor;
  }
};

inline Rational rational(const Json& value) {
  if (!value.is_object() || value.size() != 2 || !value.contains("numerator") ||
      !value.contains("denominator")) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "invalid rational object fields");
  }
  const Integer numerator = decimal(value.at("numerator"), true);
  const Integer denominator = decimal(value.at("denominator"));
  if (denominator <= 0 || gcd(numerator, denominator) != 1) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "rational input must be reduced with a positive denominator");
  }
  exact_double(numerator);
  exact_double(denominator);
  return Rational(numerator, denominator);
}

inline Rational operator+(const Rational& left, const Rational& right) {
  return {left.numerator * right.denominator + right.numerator * left.denominator,
          left.denominator * right.denominator};
}

inline Rational operator*(const Rational& left, const Rational& right) {
  return {left.numerator * right.numerator, left.denominator * right.denominator};
}

inline Rational operator/(const Rational& left, const Rational& right) {
  if (right.numerator <= 0) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "objective normalizer must be positive");
  }
  return {left.numerator * right.denominator, left.denominator * right.numerator};
}

inline Integer common_denominator(const Integer& current, const Rational& value) {
  const Integer next = current / gcd(current, value.denominator) * value.denominator;
  exact_double(next);
  return next;
}

}  // namespace dispatch::backend
