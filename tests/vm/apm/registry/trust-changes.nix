# Registry VM checks for trust changes workflows.
{
  testing,
  pkgs,
  fixtures,
}: {
  # -------------------------------------------------------------------------
  # registry-trust-keys-workflow — Committed and local trust key commands
  # -------------------------------------------------------------------------
  registry-trust-keys-workflow = testing.mkVMTest {
    name = "apm-registry-trust-keys-workflow";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: APR committed key roster and local trust store workflow"

      # Real keypairs from `apr keys generate` so roster commits can be
      # signed (required whenever the roster is non-empty).
      $APR keys generate root --registry trust-reg > /tmp/keys-generate-root.out 2>&1 || {
        cat /tmp/keys-generate-root.out
        fail "apr keys generate creates root key"
      }
      cat /tmp/keys-generate-root.out
      KEY_ROOT=$(grep -o 'trust-reg:Ed25519:[A-Za-z0-9+/=]*' /tmp/keys-generate-root.out | head -1)
      KEY_ROOT_PATH="$HOME/.config/apm/keys/trust-reg-root.key"
      assert_file_exists "$KEY_ROOT_PATH" "apr keys generate writes private key file"

      $APR keys generate backup --registry trust-reg > /tmp/keys-generate-backup.out 2>&1
      KEY_BACKUP=$(grep -o 'trust-reg:Ed25519:[A-Za-z0-9+/=]*' /tmp/keys-generate-backup.out | head -1)
      KEY_BACKUP_PATH="$HOME/.config/apm/keys/trust-reg-backup.key"

      $APR keys generate canary --registry trust-reg > /tmp/keys-generate-canary.out 2>&1
      KEY_CANARY=$(grep -o 'trust-reg:Ed25519:[A-Za-z0-9+/=]*' /tmp/keys-generate-canary.out | head -1)
      KEY_CANARY_PATH="$HOME/.config/apm/keys/trust-reg-canary.key"

      if $APR keys generate root --registry trust-reg \
        > /tmp/keys-generate-overwrite.out 2>&1; then
        cat /tmp/keys-generate-overwrite.out
        fail "apr keys generate should refuse to overwrite an existing key"
      else
        pass "apr keys generate refuses to overwrite an existing key"
      fi

      KEY_FOREIGN="other-reg:Ed25519:bWlzbWF0Y2g="

      $APR create trust-reg --trust-key "$KEY_ROOT" --trust-key-id root \
        --key "$KEY_ROOT_PATH"
      REG_DIR="$REG_STORAGE/trust-reg"
      TRUST_FILE="$HOME/.config/apm/trusted-keys.d/trust-reg.pub"
      $APR add "file://$REG_DIR" --name trust-reg --no-clone --no-verify

      assert_file_exists "$REG_DIR/keys.toml" \
        "apr create writes committed keys.toml"
      assert_file_contains "$REG_DIR/keys.toml" 'id = "root"' \
        "initial committed key id is recorded"
      assert_file_contains "$REG_DIR/keys.toml" "$KEY_ROOT" \
        "initial committed key value is recorded"

      $APR keys register backup-external --key "$KEY_BACKUP_PATH" \
        --registry trust-reg > /tmp/keys-register-path.out 2>&1 || {
        cat /tmp/keys-register-path.out
        fail "apr keys register records an existing external key path"
      }
      assert_file_contains /tmp/keys-register-path.out "$KEY_BACKUP" \
        "apr keys register reports the derived trust key"
      assert_file_contains "$HOME/.config/apm/registries.d/trust-reg.toml" \
        '"backup-external"' \
        "apr keys register persists path-backed key resolution"
      $APR keys register canary-external \
        --key-command "cat $KEY_CANARY_PATH" --registry trust-reg \
        > /tmp/keys-register-command.out 2>&1 || {
        cat /tmp/keys-register-command.out
        fail "apr keys register records an external key command"
      }
      assert_file_contains /tmp/keys-register-command.out "$KEY_CANARY" \
        "apr keys register derives a trust key from command output"
      assert_file_contains "$HOME/.config/apm/registries.d/trust-reg.toml" \
        'canary-external' \
        "apr keys register persists command-backed key resolution"

      $APR keys list --registry trust-reg > /tmp/keys-list-initial.out 2>&1 || {
        cat /tmp/keys-list-initial.out
        fail "apr keys list shows initial roster"
      }
      cat /tmp/keys-list-initial.out
      assert_file_contains /tmp/keys-list-initial.out "root:" \
        "apr keys list reports active root key"
      assert_file_contains /tmp/keys-list-initial.out "revoked: none" \
        "apr keys list reports empty revocation set"

      $APR keys add backup "$KEY_BACKUP" --key "$KEY_ROOT_PATH" --registry trust-reg \
        > /tmp/keys-add-backup.out 2>&1 || {
        cat /tmp/keys-add-backup.out
        fail "apr keys add commits backup key"
      }
      cat /tmp/keys-add-backup.out
      assert_file_contains /tmp/keys-add-backup.out "Added active signing key 'backup'" \
        "apr keys add reports backup key"
      assert_file_contains "$REG_DIR/keys.toml" 'id = "backup"' \
        "backup key is written to keys.toml"
      assert_file_contains "$REG_DIR/keys.toml" "$KEY_BACKUP" \
        "backup key value is written to keys.toml"

      $APR keys add canary "$KEY_CANARY" --key "$KEY_ROOT_PATH" --registry trust-reg \
        > /tmp/keys-add-canary.out 2>&1 || {
        cat /tmp/keys-add-canary.out
        fail "apr keys add commits canary key"
      }
      cat /tmp/keys-add-canary.out
      assert_file_contains "$REG_DIR/keys.toml" 'id = "canary"' \
        "canary key is written to keys.toml"

      if $APR keys add foreign "$KEY_FOREIGN" --key "$KEY_ROOT_PATH" --registry trust-reg \
        > /tmp/keys-add-foreign.out 2>&1; then
        cat /tmp/keys-add-foreign.out
        fail "apr keys add should reject foreign registry key"
      else
        cat /tmp/keys-add-foreign.out
        pass "apr keys add rejects foreign registry key"
      fi
      assert_file_contains /tmp/keys-add-foreign.out \
        "belongs to registry 'other-reg', expected 'trust-reg'" \
        "foreign committed key error names both registries"

      if $APR keys retire root --registry trust-reg \
        > /tmp/keys-retire-missing-vouch.out 2>&1; then
        cat /tmp/keys-retire-missing-vouch.out
        fail "apr keys retire should require --vouched-by with multiple survivors"
      else
        cat /tmp/keys-retire-missing-vouch.out
        pass "apr keys retire requires explicit vouching key"
      fi
      assert_file_contains /tmp/keys-retire-missing-vouch.out \
        "vouched-by is required" \
        "retire error explains required vouching key"

      $APR keys retire root --vouched-by backup --reason "key rotation" \
        --key "$KEY_BACKUP_PATH" \
        --registry trust-reg > /tmp/keys-retire-root.out 2>&1 || {
        cat /tmp/keys-retire-root.out
        fail "apr keys retire commits revoked root key"
      }
      cat /tmp/keys-retire-root.out
      assert_file_contains /tmp/keys-retire-root.out \
        "Retired signing key 'root'" \
        "apr keys retire reports revoked root key"
      $APR keys list --registry trust-reg > /tmp/keys-list-rotated.out 2>&1 || {
        cat /tmp/keys-list-rotated.out
        fail "apr keys list shows rotated roster"
      }
      cat /tmp/keys-list-rotated.out
      assert_file_contains /tmp/keys-list-rotated.out "backup:" \
        "rotated roster keeps backup active"
      assert_file_contains /tmp/keys-list-rotated.out "canary:" \
        "rotated roster keeps canary active"
      assert_file_contains /tmp/keys-list-rotated.out "root: key rotation" \
        "rotated roster records root revocation reason"
      git -C "$REG_DIR" log --oneline > /tmp/keys-git-log.out
      assert_file_contains /tmp/keys-git-log.out \
        "registry: add signing key backup" \
        "keys add creates a maintainer commit"
      assert_file_contains /tmp/keys-git-log.out \
        "registry: retire signing key root" \
        "keys retire creates a maintainer commit"

      $APR trust list trust-reg > /tmp/trust-list-empty.out 2>&1 || {
        cat /tmp/trust-list-empty.out
        fail "apr trust list handles empty store"
      }
      cat /tmp/trust-list-empty.out
      assert_file_contains /tmp/trust-list-empty.out "trust-reg: no pinned keys" \
        "apr trust list reports no pinned keys"

      $APR trust pin trust-reg "$KEY_ROOT" > /tmp/trust-pin-root.out 2>&1 || {
        cat /tmp/trust-pin-root.out
        fail "apr trust pin stores root key"
      }
      cat /tmp/trust-pin-root.out
      assert_file_exists "$TRUST_FILE" \
        "apr trust pin writes trusted key file"
      assert_file_contains "$TRUST_FILE" "$KEY_ROOT" \
        "trusted key file contains pinned root key"

      $APR trust pin trust-reg "$KEY_BACKUP" > /tmp/trust-pin-backup.out 2>&1 || {
        cat /tmp/trust-pin-backup.out
        fail "apr trust pin stores backup key"
      }
      cat /tmp/trust-pin-backup.out
      TRUST_COUNT=$(wc -l < "$TRUST_FILE")
      if [ "$TRUST_COUNT" = "2" ]; then
        pass "trust store keeps both pinned keys during rotation overlap"
      else
        fail "trust store should contain two pinned keys, got $TRUST_COUNT"
        cat "$TRUST_FILE"
      fi

      if $APR trust pin trust-reg "$KEY_FOREIGN" \
        > /tmp/trust-pin-foreign.out 2>&1; then
        cat /tmp/trust-pin-foreign.out
        fail "apr trust pin should reject foreign registry key"
      else
        cat /tmp/trust-pin-foreign.out
        pass "apr trust pin rejects foreign registry key"
      fi
      assert_file_contains /tmp/trust-pin-foreign.out \
        "belongs to registry 'other-reg', expected 'trust-reg'" \
        "foreign trust key error names both registries"

      $APR trust pin trust-reg "$KEY_CANARY" --replace \
        > /tmp/trust-replace.out 2>&1 || {
        cat /tmp/trust-replace.out
        fail "apr trust pin --replace stores only canary key"
      }
      cat /tmp/trust-replace.out
      TRUST_COUNT=$(wc -l < "$TRUST_FILE")
      if [ "$TRUST_COUNT" = "1" ]; then
        pass "trust replace leaves one pinned key"
      else
        fail "trust replace should leave one pinned key, got $TRUST_COUNT"
        cat "$TRUST_FILE"
      fi
      assert_file_contains "$TRUST_FILE" "$KEY_CANARY" \
        "trust replace stores canary key"

      $APR trust list trust-reg > /tmp/trust-list-canary.out 2>&1 || {
        cat /tmp/trust-list-canary.out
        fail "apr trust list shows replacement key"
      }
      cat /tmp/trust-list-canary.out
      assert_file_contains /tmp/trust-list-canary.out "trust-reg: Ed25519" \
        "apr trust list reports pinned canary key"

      $APR trust remove trust-reg > /tmp/trust-remove.out 2>&1 || {
        cat /tmp/trust-remove.out
        fail "apr trust remove deletes trust file"
      }
      cat /tmp/trust-remove.out
      assert_file_not_exists "$TRUST_FILE" \
        "apr trust remove deletes trusted key file"
      $APR trust remove trust-reg > /tmp/trust-remove-repeat.out 2>&1 || {
        cat /tmp/trust-remove-repeat.out
        fail "apr trust remove is idempotent"
      }
      cat /tmp/trust-remove-repeat.out
      assert_file_contains /tmp/trust-remove-repeat.out \
        "No pinned trust keys found" \
        "repeat trust remove reports no pinned keys"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-change-workflow — Review and promote Hub-authored Git changes
  # -------------------------------------------------------------------------
  registry-change-workflow = testing.mkVMTest {
    name = "apm-registry-change-workflow";
    rootfsDeps = fixtures.commonDeps ++ [pkgs.jq];
    memory = 512;
    testScript = ''
            ${fixtures.setupPreamble}

            echo "==> Test: APR lists, reviews, and promotes a Hub change request"

            $APR keys generate maintainer --registry change-reg \
              > /tmp/change-key.out 2>&1
            TRUST_KEY=$(grep -o 'change-reg:Ed25519:[A-Za-z0-9+/=]*' \
              /tmp/change-key.out | head -1)
            KEY_PATH="$HOME/.config/apm/keys/change-reg-maintainer.key"
            $APR create change-reg --trust-key "$TRUST_KEY" \
              --trust-key-id maintainer --key "$KEY_PATH"
            REG_DIR="$REG_STORAGE/change-reg"
            DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

            git init --bare --object-format=sha256 /tmp/change-origin.git
            git --git-dir=/tmp/change-origin.git symbolic-ref HEAD \
              "refs/heads/$DEFAULT_BRANCH"
            git -C "$REG_DIR" remote add origin /tmp/change-origin.git
            $APR add file:///tmp/change-origin.git --name change-reg --no-clone \
              --trust-key "$TRUST_KEY"
            $APR keys register maintainer --key "$KEY_PATH" --registry change-reg
            git -C "$REG_DIR" push --set-upstream origin "$DEFAULT_BRANCH"

            BASE_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
            printf '%s\n' '# reviewed Hub configuration fixture' \
              >> "$REG_DIR/registry.toml"
            git -C "$REG_DIR" add registry.toml
            git -C "$REG_DIR" commit -m \
              'hub: propose registry configuration

      AOS-Change-Id: change-001'
            DRAFT_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
            git -C "$REG_DIR" push origin \
              "$DRAFT_COMMIT:refs/hub/changes/change-001"
            git -C "$REG_DIR" reset --hard "$BASE_COMMIT"

            $APR --json change list --registry change-reg \
              > /tmp/change-list.json 2> /tmp/change-list.err || {
              cat /tmp/change-list.err
              fail "apr change list reads Hub change refs from the configured remote"
            }
            ${pkgs.jq}/bin/jq -e --arg commit "$DRAFT_COMMIT" \
              '.change_requests | length == 1
                and .[0].id == "change-001"
                and .[0].commit == $commit
                and .[0].change_id == "change-001"' \
              /tmp/change-list.json >/dev/null
            $APR change show change-001 --registry change-reg \
              > /tmp/change-show.out 2>&1
            assert_file_contains /tmp/change-show.out \
              'reviewed Hub configuration fixture' \
              "apr change show displays the proposed configuration"
            $APR --json change show change-001 --stat --registry change-reg \
              > /tmp/change-show-stat.json
            ${pkgs.jq}/bin/jq -e \
              '.id == "change-001" and .stat == true and (.output | contains("registry.toml"))' \
              /tmp/change-show-stat.json >/dev/null

            $APR --json change merge change-001 --key-id maintainer \
              --registry change-reg > /tmp/change-merge.json
            ${pkgs.jq}/bin/jq -e \
              --arg draft "$DRAFT_COMMIT" --arg branch "$DEFAULT_BRANCH" \
              '.id == "change-001"
                and .branch == $branch
                and .promoted_from == $draft
                and (.commit | length == 64)' \
              /tmp/change-merge.json >/dev/null
            assert_file_contains "$REG_DIR/registry.toml" \
              'reviewed Hub configuration fixture' \
              "apr change merge promotes the reviewed tree"
            LOCAL_HEAD=$(git -C "$REG_DIR" rev-parse HEAD)
            REMOTE_HEAD=$(git --git-dir=/tmp/change-origin.git \
              rev-parse "refs/heads/$DEFAULT_BRANCH")
            test "$LOCAL_HEAD" = "$REMOTE_HEAD" || \
              fail "apr change merge must push the promoted commit"
            git -C "$REG_DIR" cat-file commit HEAD > /tmp/change-commit.out
            assert_file_contains /tmp/change-commit.out 'gpgsig-sha256 ' \
              "promoted change carries a maintainer signature"

            if $APR change show missing --registry change-reg \
              > /tmp/change-show-missing.out 2>&1; then
              fail "apr change show should reject an unknown change id"
            else
              pass "apr change show rejects an unknown change id"
            fi

            check_fail
    '';
  };
}
