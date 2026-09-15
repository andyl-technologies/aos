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
]
