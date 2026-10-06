# This separate AGPL Garage variant disposes refused UploadPart bodies before
# replying. The ordinary package and its default configuration stay unchanged.
{pkgs}:
pkgs.garage.overrideAttrs (previous: {
  pname = "garage-fleet-refusal-drain";
  patches = (previous.patches or []) ++ [../../pkgs/storage/garage-patches/0001-fixture-refusal-drain.patch];
  postPatch = (previous.postPatch or "") + ''
    mkdir -p src/api/common/signature/body
    cp ${../../pkgs/storage/garage-patches/fixture-refusal-drain.rs} \
      src/api/common/signature/body/fixture_refusal.rs
  '';
  doCheck = true;
  cargoTestFlags = "-p garage_api_common -p garage_util --lib fixture_refusal";
})
