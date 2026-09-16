##! Small, independently authored portable-schema behavior vectors.
let
  accept = id: schema: value: {
    inherit id schema value;
    expected = {
      outcome = "accept";
      inherit value;
    };
  };
  reject = id: schema: value: {
    inherit id schema value;
    expected = {
      outcome = "reject";
      code = "value-type-mismatch";
    };
  };
  localKey = {
    kind = "string";
    max_length = 128;
    syntax = "local-key-v1";
  };
  record = {
    kind = "record";
    fields = {
      enabled = {kind = "boolean";};
      name = localKey;
    };
    optional_fields = ["name"];
  };
  tagged = {
    kind = "tagged-union";
    tag = "kind";
    variants = {
      ready = {
        kind = "record";
        fields = {
          kind = {
            kind = "string-enum";
            values = ["ready"];
          };
          value = {kind = "boolean";};
        };
        optional_fields = [];
      };
      waiting = {
        kind = "record";
        fields.kind = {
          kind = "string-enum";
          values = ["waiting"];
        };
        optional_fields = [];
      };
    };
  };
  refinedString = pattern: {
    kind = "refined";
    value = {
      kind = "string";
      max_length = 128;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        inherit pattern;
      }
    ];
  };
  uuidPattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
  partitionKindPattern = "(linux-generic|swap|${uuidPattern})";
in [
  (accept "boolean-valid" {kind = "boolean";} true)
  (reject "boolean-wrong-type" {kind = "boolean";} "true")
  (accept "integer-upper-bound" {
      kind = "integer";
      minimum = -7;
      maximum = 19;
    }
    19)
  (reject "integer-over-bound" {
      kind = "integer";
      minimum = -7;
      maximum = 19;
    }
    20)
  (accept "local-key-valid" localKey "service.unit-1")
  (reject "local-key-invalid" localKey "service/unit")
  (accept "record-optional-omitted" record {enabled = true;})
  (reject "record-unknown-field" record {
    enabled = true;
    unknown = false;
  })
  (accept "tagged-union-valid" tagged {
    kind = "ready";
    value = true;
  })
  (reject "tagged-union-wrong-variant" tagged {kind = "unknown";})
  (accept "refined-uuid-valid" (refinedString uuidPattern) "12345678-1234-1234-1234-123456789abc")
  (reject "refined-uuid-uppercase" (refinedString uuidPattern) "12345678-1234-1234-1234-123456789ABC")
  (accept "refined-stable-device-valid" (refinedString "/dev/disk/by-id/[A-Za-z0-9._:+-]+") "/dev/disk/by-id/nvme-Example_1")
  (reject "refined-stable-device-empty" (refinedString "/dev/disk/by-id/[A-Za-z0-9._:+-]+") "/dev/disk/by-id/")
  (accept "refined-positive-size-valid" (refinedString "[1-9][0-9]*[KMGTP]?") "16G")
  (reject "refined-positive-size-zero" (refinedString "[1-9][0-9]*[KMGTP]?") "0G")
  (accept "refined-partition-alias-valid" (refinedString partitionKindPattern) "linux-generic")
  (accept "refined-partition-uuid-valid" (refinedString partitionKindPattern) "12345678-1234-1234-1234-123456789abc")
  (reject "refined-partition-kind-invalid" (refinedString partitionKindPattern) "linux-home")
  (reject "refined-nonportable-backreference" (refinedString "([a])\\1") "aa")
]
