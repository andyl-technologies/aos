# Registry VM checks for branches workflows.
{
  testing,
  pkgs,
  fixtures,
  setupNixPublishEnv,
  closureLeafTool,
  closureRootTool,
  closureWorkflowDeps,
}: {
  # -------------------------------------------------------------------------
  # registry-branch-workflow — Branch create, switch, merge modes, pull
  # -------------------------------------------------------------------------
  registry-branch-workflow = testing.mkVMTest {
    name = "apm-registry-branch-workflow";
    rootfsDeps = closureWorkflowDeps ++ [pkgs.jq];
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR branch create, switch, publish, merge modes, pull"
      export GIT_MERGE_AUTOEDIT=no

      FEATURE_STORE="${closureRootTool}"
      FEATURE_DEP_STORE="${closureLeafTool}"
      FEATURE_HASH=$(basename "$FEATURE_STORE" | cut -d- -f1)
      FEATURE_DEP_HASH=$(basename "$FEATURE_DEP_STORE" | cut -d- -f1)

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      publish_feature_package() {
        $APR publish "$FEATURE_STORE" \
          --name featurepkg \
          --version 1.0.0 \
          --description "Real branch workflow fixture" \
          --license MIT \
          --maintainer branch@example.invalid \
          --registry test-reg \
          --no-commit > /tmp/branch-publish.out 2>&1 || {
          cat /tmp/branch-publish.out
          fail "apr publish featurepkg on feature branch succeeds"
          return 1
        }
        cat /tmp/branch-publish.out
      }

      commit_branch_changes() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message" > /tmp/branch-commit.out 2>&1 || {
          cat /tmp/branch-commit.out
          fail "registry commit succeeds: $message"
          return 1
        }
        cat /tmp/branch-commit.out
      }

      mount -o remount,rw / || true
      nix-store -q --references "$FEATURE_STORE" > /tmp/branch-feature-refs.out
      assert_file_contains /tmp/branch-feature-refs.out "$FEATURE_DEP_STORE" \
        "feature package has a real Nix reference to its dependency"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR --json branch create json-branch --registry test-reg \
        > /tmp/branch-json-create.json 2>&1 || {
        cat /tmp/branch-json-create.json
        fail "apr --json branch create succeeds"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "create"
          and .branch == "json-branch"
          and .current == $default
          and (.branches | any(.name == "json-branch" and .current == false and .remote == false))
          and (.branches | any(.name == $default and .current == true and .remote == false))' \
        /tmp/branch-json-create.json >/dev/null || {
        cat /tmp/branch-json-create.json
        fail "apr --json branch create reports created branch"
      }
      pass "apr --json branch create reports created branch"
      $APR --json branch delete json-branch --registry test-reg \
        > /tmp/branch-json-delete.json 2>&1 || {
        cat /tmp/branch-json-delete.json
        fail "apr --json branch delete succeeds"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "delete"
          and .branch == "json-branch"
          and .current == $default
          and (.branches | all(.name != "json-branch"))
          and (.branches | any(.name == $default and .current == true and .remote == false))' \
        /tmp/branch-json-delete.json >/dev/null || {
        cat /tmp/branch-json-delete.json
        fail "apr --json branch delete reports deleted branch"
      }
      pass "apr --json branch delete reports deleted branch"

      $APR branch create feature-1 --registry test-reg > /tmp/branch-create.out 2>&1 || {
        cat /tmp/branch-create.out
        fail "apr branch create succeeds"
      }
      cat /tmp/branch-create.out
      assert_file_contains /tmp/branch-create.out "Created branch 'feature-1'" \
        "apr branch create reports feature branch"

      $APR --json branch switch feature-1 --registry test-reg \
        > /tmp/branch-switch-feature.json 2>&1 || {
        cat /tmp/branch-switch-feature.json
        fail "apr --json branch switch feature-1 succeeds"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "switch"
          and .branch == "feature-1"
          and .current == "feature-1"
          and (.branches | any(.name == "feature-1" and .current == true and .remote == false))
          and (.branches | any(.name == $default and .current == false and .remote == false))' \
        /tmp/branch-switch-feature.json >/dev/null || {
        cat /tmp/branch-switch-feature.json
        fail "apr --json branch switch reports feature branch as current"
      }
      pass "apr --json branch switch reports feature branch as current"
      $APR branch switch feature-1 --registry test-reg > /tmp/branch-switch-feature.out 2>&1 || {
        cat /tmp/branch-switch-feature.out
        fail "apr branch switch feature-1 succeeds"
      }
      cat /tmp/branch-switch-feature.out
      assert_file_contains /tmp/branch-switch-feature.out "Switched to branch 'feature-1'" \
        "apr branch switch reports feature branch"
      $APR --json branch list --registry test-reg \
        > /tmp/branch-list-feature-current.json 2>&1 || {
        cat /tmp/branch-list-feature-current.json
        fail "apr --json branch list succeeds on feature branch"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.branches
          | (any(.name == "feature-1" and .current == true and .remote == false)
            and any(.name == $default and .current == false and .remote == false))' \
        /tmp/branch-list-feature-current.json >/dev/null || {
        cat /tmp/branch-list-feature-current.json
        fail "apr --json branch list reports feature branch as current"
      }
      pass "apr --json branch list reports feature branch as current"

      publish_feature_package
      commit_branch_changes "publish featurepkg 1.0.0 on feature branch"
      assert_file_exists "$REG_DIR/packages/f/featurepkg.toml" \
        "published package exists on feature branch"
      assert_file_contains "$REG_DIR/packages/f/featurepkg.toml" "$FEATURE_HASH" \
        "feature branch package metadata records real store hash"
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$FEATURE_HASH")/$FEATURE_HASH" \
        "feature branch store record exists"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$FEATURE_HASH")/$FEATURE_HASH" "$FEATURE_DEP_HASH" \
        "feature branch store record lists dependency edge"

      $APR packages --registry test-reg > /tmp/branch-packages-feature.out 2>&1 || {
        cat /tmp/branch-packages-feature.out
        fail "apr packages lists feature branch package"
      }
      assert_file_contains /tmp/branch-packages-feature.out "featurepkg 1.0.0" \
        "apr packages sees feature package on feature branch"
      $APR --json packages --registry test-reg \
        > /tmp/branch-packages-feature.json 2>&1 || {
        cat /tmp/branch-packages-feature.json
        fail "apr --json packages lists feature branch package"
      }
      ${pkgs.jq}/bin/jq -e \
        'length == 1 and .[0].name == "featurepkg" and .[0].version == "1.0.0"' \
        /tmp/branch-packages-feature.json >/dev/null || {
        cat /tmp/branch-packages-feature.json
        fail "apr --json packages sees feature package on feature branch"
      }
      pass "apr --json packages sees feature package on feature branch"
      $APR verify --registry test-reg > /tmp/branch-verify-feature.out 2>&1 || {
        cat /tmp/branch-verify-feature.out
        fail "apr verify accepts feature branch package"
      }
      assert_file_contains /tmp/branch-verify-feature.out "no errors" \
        "apr verify validates feature branch closure metadata"

      $APR branch switch "$DEFAULT_BRANCH" --registry test-reg > /tmp/branch-switch-default.out 2>&1 || {
        cat /tmp/branch-switch-default.out
        fail "apr branch switch default succeeds"
      }
      cat /tmp/branch-switch-default.out
      assert_file_contains /tmp/branch-switch-default.out "Switched to branch '$DEFAULT_BRANCH'" \
        "apr branch switch reports default branch"
      $APR --json branch list --registry test-reg \
        > /tmp/branch-list-default-current.json 2>&1 || {
        cat /tmp/branch-list-default-current.json
        fail "apr --json branch list succeeds on default branch"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.branches
          | (any(.name == $default and .current == true and .remote == false)
            and any(.name == "feature-1" and .current == false and .remote == false))' \
        /tmp/branch-list-default-current.json >/dev/null || {
        cat /tmp/branch-list-default-current.json
        fail "apr --json branch list reports default branch as current"
      }
      pass "apr --json branch list reports default branch as current"

      assert_file_not_exists "$REG_DIR/packages/f/featurepkg.toml" \
        "package not on default branch before merge"
      assert_file_not_exists "$REG_DIR/store/$(printf %.2s "$FEATURE_HASH")/$FEATURE_HASH" \
        "store record not on default branch before merge"
      $APR packages --registry test-reg > /tmp/branch-packages-default.out 2>&1 || {
        cat /tmp/branch-packages-default.out
        fail "apr packages succeeds on default branch before merge"
      }
      assert_file_not_contains /tmp/branch-packages-default.out "featurepkg" \
        "apr packages hides feature package before merge"
      $APR --json packages --registry test-reg \
        > /tmp/branch-packages-default.json 2>&1 || {
        cat /tmp/branch-packages-default.json
        fail "apr --json packages succeeds on default branch before merge"
      }
      ${pkgs.jq}/bin/jq -e 'length == 0' \
        /tmp/branch-packages-default.json >/dev/null || {
        cat /tmp/branch-packages-default.json
        fail "apr --json packages hides feature package before merge"
      }
      pass "apr --json packages hides feature package before merge"

      $APR --json merge feature-1 --registry test-reg > /tmp/branch-merge.json 2>&1 || {
        cat /tmp/branch-merge.json
        fail "apr merge feature branch succeeds"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "merge"
          and .branch == "feature-1"
          and .no_ff == false
          and .squash == false
          and .current == $default
          and (.head | length == 64)
          and (.output | contains("Fast-forward"))
          and (.branches | any(.name == $default and .current == true))' \
        /tmp/branch-merge.json >/dev/null || {
        cat /tmp/branch-merge.json
        fail "apr --json merge reports merged branch"
      }
      pass "apr --json merge reports merged branch"

      assert_file_exists "$REG_DIR/packages/f/featurepkg.toml" \
        "package exists on default branch after merge"
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$FEATURE_HASH")/$FEATURE_HASH" \
        "store record exists on default branch after merge"
      $APR show featurepkg --registry test-reg > /tmp/branch-show-merged.out 2>&1 || {
        cat /tmp/branch-show-merged.out
        fail "apr show resolves merged package"
      }
      assert_file_contains /tmp/branch-show-merged.out "Real branch workflow fixture" \
        "apr show displays merged package metadata"
      $APR --json show featurepkg --registry test-reg \
        > /tmp/branch-show-merged.json 2>&1 || {
        cat /tmp/branch-show-merged.json
        fail "apr --json show resolves merged package"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg store "$FEATURE_STORE" \
        '.package.name == "featurepkg"
          and .package.description == "Real branch workflow fixture"
          and .versions[0].version == "1.0.0"
          and .versions[0].platforms."x86_64-linux".store_path == $store' \
        /tmp/branch-show-merged.json >/dev/null || {
        cat /tmp/branch-show-merged.json
        fail "apr --json show displays merged closure metadata"
      }
      pass "apr --json show displays merged closure metadata"
      $APR verify --registry test-reg > /tmp/branch-verify-merged.out 2>&1 || {
        cat /tmp/branch-verify-merged.out
        fail "apr verify accepts merged branch package"
      }
      assert_file_contains /tmp/branch-verify-merged.out "no errors" \
        "apr verify validates merged closure metadata"
      $APR branch list --registry test-reg > /tmp/branch-list.out 2>&1 || {
        cat /tmp/branch-list.out
        fail "apr branch list succeeds"
      }
      assert_file_contains /tmp/branch-list.out "feature-1" \
        "apr branch list shows feature branch"
      $APR --json branch list --registry test-reg > /tmp/branch-list.json 2>&1 || {
        cat /tmp/branch-list.json
        fail "apr --json branch list succeeds"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.branches
          | (any(.name == $default and .current == true and .remote == false)
            and any(.name == "feature-1" and .current == false and .remote == false))' \
        /tmp/branch-list.json >/dev/null || {
        cat /tmp/branch-list.json
        fail "apr --json branch list shows merged feature branch"
      }
      pass "apr --json branch list shows merged feature branch"

      $APR branch delete feature-1 --registry test-reg \
        > /tmp/branch-delete.out 2>&1 || {
        cat /tmp/branch-delete.out
        fail "apr branch delete removes merged feature branch"
      }
      cat /tmp/branch-delete.out
      assert_file_contains /tmp/branch-delete.out "Deleted branch 'feature-1'" \
        "apr branch delete reports deleted feature branch"
      $APR branch list --registry test-reg > /tmp/branch-list-after-delete.out 2>&1 || {
        cat /tmp/branch-list-after-delete.out
        fail "apr branch list succeeds after delete"
      }
      assert_file_not_contains /tmp/branch-list-after-delete.out "feature-1" \
        "apr branch list hides deleted feature branch"
      $APR --json branch list --registry test-reg \
        > /tmp/branch-list-after-delete.json 2>&1 || {
        cat /tmp/branch-list-after-delete.json
        fail "apr --json branch list succeeds after delete"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.branches
          | (any(.name == $default and .current == true and .remote == false)
            and all(.name != "feature-1"))' \
        /tmp/branch-list-after-delete.json >/dev/null || {
        cat /tmp/branch-list-after-delete.json
        fail "apr --json branch list hides deleted feature branch"
      }
      pass "apr --json branch list hides deleted feature branch"

      echo "==> Test: APR merge --no-ff keeps an explicit maintainer merge commit"

      $APR branch create noff-branch --registry test-reg \
        > /tmp/branch-noff-create.out 2>&1 || {
        cat /tmp/branch-noff-create.out
        fail "apr branch create succeeds for no-ff branch"
      }
      cat /tmp/branch-noff-create.out
      $APR branch switch noff-branch --registry test-reg \
        > /tmp/branch-noff-switch.out 2>&1 || {
        cat /tmp/branch-noff-switch.out
        fail "apr branch switch succeeds for no-ff branch"
      }
      cat /tmp/branch-noff-switch.out

      $APR publish "$FEATURE_DEP_STORE" \
        --name noffpkg \
        --version 1.0.0 \
        --description "No-ff maintainer merge fixture" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/branch-noff-publish.out 2>&1 || {
        cat /tmp/branch-noff-publish.out
        fail "apr publish creates package on no-ff branch"
      }
      cat /tmp/branch-noff-publish.out
      commit_branch_changes "publish noffpkg 1.0.0 on no-ff branch"

      $APR branch switch "$DEFAULT_BRANCH" --registry test-reg \
        > /tmp/branch-noff-switch-default.out 2>&1 || {
        cat /tmp/branch-noff-switch-default.out
        fail "apr branch switch returns to default before no-ff merge"
      }
      cat /tmp/branch-noff-switch-default.out

      $APR --json merge noff-branch --no-ff --registry test-reg \
        > /tmp/branch-noff-merge.json 2>&1 || {
        cat /tmp/branch-noff-merge.json
        fail "apr merge --no-ff succeeds"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "merge"
          and .branch == "noff-branch"
          and .no_ff == true
          and .squash == false
          and .current == $default
          and (.head | length == 64)
          and (.branches | any(.name == $default and .current == true))' \
        /tmp/branch-noff-merge.json >/dev/null || {
        cat /tmp/branch-noff-merge.json
        fail "apr --json merge --no-ff reports merged branch"
      }
      pass "apr --json merge --no-ff reports merged branch"
      NOFF_HEAD_PARENTS=$(git -C "$REG_DIR" rev-list --parents -n 1 HEAD | wc -w)
      if [ "$NOFF_HEAD_PARENTS" = "3" ]; then
        pass "apr merge --no-ff creates a two-parent merge commit"
      else
        fail "apr merge --no-ff should leave three rev-list fields, got $NOFF_HEAD_PARENTS"
        git -C "$REG_DIR" log --oneline --graph -5
      fi
      $APR show noffpkg --registry test-reg > /tmp/branch-noff-show.out 2>&1 || {
        cat /tmp/branch-noff-show.out
        fail "apr show resolves no-ff merged package"
      }
      assert_file_contains /tmp/branch-noff-show.out "No-ff maintainer merge fixture" \
        "apr show displays no-ff merged package metadata"
      $APR verify --registry test-reg > /tmp/branch-noff-verify.out 2>&1 || {
        cat /tmp/branch-noff-verify.out
        fail "apr verify accepts no-ff merged package"
      }
      assert_file_contains /tmp/branch-noff-verify.out "no errors" \
        "apr verify validates no-ff merged registry metadata"
      $APR branch delete noff-branch --registry test-reg \
        > /tmp/branch-noff-delete.out 2>&1 || {
        cat /tmp/branch-noff-delete.out
        fail "apr branch delete removes no-ff merged branch"
      }
      cat /tmp/branch-noff-delete.out

      echo "==> Test: APR merge --squash stages a maintainer changeset"

      $APR branch create squash-branch --registry test-reg \
        > /tmp/branch-squash-create.out 2>&1 || {
        cat /tmp/branch-squash-create.out
        fail "apr branch create succeeds for squash branch"
      }
      cat /tmp/branch-squash-create.out
      $APR branch switch squash-branch --registry test-reg \
        > /tmp/branch-squash-switch.out 2>&1 || {
        cat /tmp/branch-squash-switch.out
        fail "apr branch switch succeeds for squash branch"
      }
      cat /tmp/branch-squash-switch.out

      $APR publish "$FEATURE_STORE" \
        --name squashpkg \
        --version 1.0.0 \
        --description "Squash maintainer changeset fixture" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/branch-squash-publish.out 2>&1 || {
        cat /tmp/branch-squash-publish.out
        fail "apr publish creates package on squash branch"
      }
      cat /tmp/branch-squash-publish.out
      commit_branch_changes "publish squashpkg 1.0.0 on squash branch"
      SQUASH_BRANCH_HEAD=$(git -C "$REG_DIR" rev-parse HEAD)

      $APR branch switch "$DEFAULT_BRANCH" --registry test-reg \
        > /tmp/branch-squash-switch-default.out 2>&1 || {
        cat /tmp/branch-squash-switch-default.out
        fail "apr branch switch returns to default before squash merge"
      }
      cat /tmp/branch-squash-switch-default.out
      DEFAULT_BEFORE_SQUASH=$(git -C "$REG_DIR" rev-parse HEAD)

      $APR --json merge squash-branch --squash --registry test-reg \
        > /tmp/branch-squash-merge.json 2>&1 || {
        cat /tmp/branch-squash-merge.json
        fail "apr merge --squash stages changes"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg default "$DEFAULT_BRANCH" \
        --arg before "$DEFAULT_BEFORE_SQUASH" \
        '.action == "merge"
          and .branch == "squash-branch"
          and .no_ff == false
          and .squash == true
          and .current == $default
          and .head == $before
          and (.branches | any(.name == $default and .current == true))' \
        /tmp/branch-squash-merge.json >/dev/null || {
        cat /tmp/branch-squash-merge.json
        fail "apr --json merge --squash reports staged branch"
      }
      pass "apr --json merge --squash reports staged branch"
      CURRENT_AFTER_SQUASH=$(git -C "$REG_DIR" rev-parse HEAD)
      if [ "$CURRENT_AFTER_SQUASH" = "$DEFAULT_BEFORE_SQUASH" ]; then
        pass "apr merge --squash does not advance HEAD before maintainer commit"
      else
        fail "apr merge --squash advanced HEAD before the maintainer commit"
        git -C "$REG_DIR" log --oneline --graph -5
      fi
      $APR status --registry test-reg > /tmp/branch-squash-status.out 2>&1 || {
        cat /tmp/branch-squash-status.out
        fail "apr status succeeds after squash merge"
      }
      assert_file_contains /tmp/branch-squash-status.out "packages/s/squashpkg.toml" \
        "apr status shows staged squash package metadata"
      $APR show squashpkg --registry test-reg > /tmp/branch-squash-show-staged.out 2>&1 || {
        cat /tmp/branch-squash-show-staged.out
        fail "apr show resolves staged squash package"
      }
      assert_file_contains /tmp/branch-squash-show-staged.out \
        "Squash maintainer changeset fixture" \
        "apr show displays staged squash package metadata"
      $APR verify --registry test-reg > /tmp/branch-squash-verify-staged.out 2>&1 || {
        cat /tmp/branch-squash-verify-staged.out
        fail "apr verify accepts staged squash package"
      }
      assert_file_contains /tmp/branch-squash-verify-staged.out "no errors" \
        "apr verify validates staged squash registry metadata"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "squash merge squashpkg 1.0.0" \
        > /tmp/branch-squash-commit.out 2>&1 || {
        cat /tmp/branch-squash-commit.out
        fail "maintainer commits squash merge result"
      }
      cat /tmp/branch-squash-commit.out
      SQUASH_HEAD_PARENTS=$(git -C "$REG_DIR" rev-list --parents -n 1 HEAD | wc -w)
      if [ "$SQUASH_HEAD_PARENTS" = "2" ]; then
        pass "apr merge --squash keeps a linear maintainer commit"
      else
        fail "apr merge --squash should leave two rev-list fields, got $SQUASH_HEAD_PARENTS"
        git -C "$REG_DIR" log --oneline --graph -5
      fi
      if git -C "$REG_DIR" merge-base --is-ancestor "$SQUASH_BRANCH_HEAD" HEAD; then
        fail "squash branch commit should not become an ancestor of default"
        git -C "$REG_DIR" log --oneline --graph -8
      else
        pass "squash branch remains a non-ancestor after squash commit"
      fi
      $APR verify --registry test-reg > /tmp/branch-squash-verify.out 2>&1 || {
        cat /tmp/branch-squash-verify.out
        fail "apr verify accepts committed squash package"
      }
      assert_file_contains /tmp/branch-squash-verify.out "no errors" \
        "apr verify validates committed squash registry metadata"
      if $APR branch delete squash-branch --registry test-reg \
        > /tmp/branch-squash-delete.out 2>&1; then
        cat /tmp/branch-squash-delete.out
        fail "apr branch delete should reject a squash-only branch"
      else
        cat /tmp/branch-squash-delete.out
        pass "apr branch delete preserves unmerged squash branch"
      fi
      git -C "$REG_DIR" branch -D squash-branch \
        > /tmp/branch-squash-force-delete.out 2>&1 || {
        cat /tmp/branch-squash-force-delete.out
        fail "test cleanup force-deletes squash branch"
      }
      cat /tmp/branch-squash-force-delete.out

      echo "==> Test: APR pull and pull --rebase between maintainer clones"

      git init --bare --object-format=sha256 /tmp/branch-origin.git
      git -C "$REG_DIR" remote add origin /tmp/branch-origin.git
      git --git-dir=/tmp/branch-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      $APR --json push --registry test-reg --set-upstream \
        > /tmp/branch-initial-push.json 2>&1 || {
        cat /tmp/branch-initial-push.json
        fail "apr push --set-upstream publishes current default branch"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg default "$DEFAULT_BRANCH" \
        --arg remote "origin/$DEFAULT_BRANCH" \
        '.action == "push"
          and .branch == $default
          and .set_upstream == true
          and .force == false
          and .current == $default
          and (.head | length == 64)
          and (.branches | any(.name == $remote and .remote == true))' \
        /tmp/branch-initial-push.json >/dev/null || {
        cat /tmp/branch-initial-push.json
        fail "apr --json push --set-upstream reports current branch push"
      }
      pass "apr --json push --set-upstream reports current branch push"
      $APR --json branch list --registry test-reg \
        > /tmp/branch-list-after-push.json 2>&1 || {
        cat /tmp/branch-list-after-push.json
        fail "apr --json branch list succeeds after pushing default branch"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg default "$DEFAULT_BRANCH" \
        --arg remote "origin/$DEFAULT_BRANCH" \
        '.branches
          | (any(.name == $default and .current == true and .remote == false)
            and any(.name == $remote and .current == false and .remote == true))' \
        /tmp/branch-list-after-push.json >/dev/null || {
        cat /tmp/branch-list-after-push.json
        fail "apr --json branch list reports remote tracking branch"
      }
      pass "apr --json branch list reports remote tracking branch"

      COLLAB_DIR="$REG_STORAGE/collab-reg"
      git clone /tmp/branch-origin.git "$COLLAB_DIR" \
        > /tmp/branch-collab-clone.out 2>&1 || {
        cat /tmp/branch-collab-clone.out
        fail "second maintainer clone succeeds"
      }
      cat /tmp/branch-collab-clone.out
      $APR show featurepkg --registry collab-reg \
        > /tmp/branch-collab-show-feature.out 2>&1 || {
        cat /tmp/branch-collab-show-feature.out
        fail "second maintainer clone can query merged package"
      }
      assert_file_contains /tmp/branch-collab-show-feature.out \
        "Real branch workflow fixture" \
        "second maintainer clone sees merged package metadata"

      $APR publish "$FEATURE_DEP_STORE" \
        --name collab-local \
        --version 1.0.0 \
        --description "Local collaborator package before rebase" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry collab-reg \
        --no-commit > /tmp/branch-collab-local-publish.out 2>&1 || {
        cat /tmp/branch-collab-local-publish.out
        fail "second maintainer publishes local package before pull --rebase"
      }
      cat /tmp/branch-collab-local-publish.out
      git -C "$COLLAB_DIR" add -A
      git -C "$COLLAB_DIR" commit -m "publish collaborator local package" \
        > /tmp/branch-collab-local-commit.out 2>&1 || {
        cat /tmp/branch-collab-local-commit.out
        fail "second maintainer commits local package before pull --rebase"
      }
      cat /tmp/branch-collab-local-commit.out

      $APR publish "$FEATURE_STORE" \
        --name remote-added \
        --version 1.0.0 \
        --description "Remote maintainer package for pull workflow" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/branch-remote-added-publish.out 2>&1 || {
        cat /tmp/branch-remote-added-publish.out
        fail "first maintainer publishes remote package"
      }
      cat /tmp/branch-remote-added-publish.out
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish remote added package" \
        > /tmp/branch-remote-added-commit.out 2>&1 || {
        cat /tmp/branch-remote-added-commit.out
        fail "first maintainer commits remote package"
      }
      cat /tmp/branch-remote-added-commit.out
      $APR --json diff --registry test-reg --remote --stat \
        > /tmp/branch-primary-ahead-diff.json 2>&1 || {
        cat /tmp/branch-primary-ahead-diff.json
        fail "apr diff --remote reports local commit ahead of upstream"
      }
      ${pkgs.jq}/bin/jq -e \
        '.remote == true
          and .stat == true
          and .clean == false
          and (.changed_files | any(.status == "A" and .path == "packages/r/remote-added.toml"))
          and (.output | contains("packages/r/remote-added.toml"))' \
        /tmp/branch-primary-ahead-diff.json >/dev/null || {
        cat /tmp/branch-primary-ahead-diff.json
        fail "apr --json diff --remote reports unpushed maintainer package"
      }
      pass "apr --json diff --remote reports unpushed maintainer package"
      $APR push --registry test-reg --branch "$DEFAULT_BRANCH" \
        > /tmp/branch-remote-added-push.out 2>&1 || {
        cat /tmp/branch-remote-added-push.out
        fail "first maintainer pushes remote package"
      }
      cat /tmp/branch-remote-added-push.out

      $APR packages --registry collab-reg > /tmp/branch-collab-before-rebase.out 2>&1 || {
        cat /tmp/branch-collab-before-rebase.out
        fail "second maintainer lists packages before pull --rebase"
      }
      assert_file_contains /tmp/branch-collab-before-rebase.out "collab-local" \
        "second maintainer sees local package before pull --rebase"
      assert_file_not_contains /tmp/branch-collab-before-rebase.out "remote-added" \
        "second maintainer does not see remote package before pull --rebase"

      $APR --json pull --registry collab-reg --rebase > /tmp/branch-collab-rebase.json 2>&1 || {
        cat /tmp/branch-collab-rebase.json
        fail "apr pull --rebase updates second maintainer clone"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "pull"
          and .rebase == true
          and .current == $default
          and (.head | length == 64)
          and (.branches | any(.name == $default and .current == true))' \
        /tmp/branch-collab-rebase.json >/dev/null || {
        cat /tmp/branch-collab-rebase.json
        fail "apr --json pull --rebase reports rebased maintainer clone"
      }
      pass "apr --json pull --rebase reports rebased maintainer clone"
      $APR packages --registry collab-reg > /tmp/branch-collab-after-rebase.out 2>&1 || {
        cat /tmp/branch-collab-after-rebase.out
        fail "second maintainer lists packages after pull --rebase"
      }
      assert_file_contains /tmp/branch-collab-after-rebase.out "collab-local" \
        "pull --rebase preserves local maintainer package"
      assert_file_contains /tmp/branch-collab-after-rebase.out "remote-added" \
        "pull --rebase imports remote maintainer package"
      $APR verify --registry collab-reg > /tmp/branch-collab-verify.out 2>&1 || {
        cat /tmp/branch-collab-verify.out
        fail "rebased maintainer clone verifies"
      }
      assert_file_contains /tmp/branch-collab-verify.out "no errors" \
        "rebased maintainer clone has valid registry metadata"
      COLLAB_HEAD_PARENTS=$(git -C "$COLLAB_DIR" rev-list --parents -n 1 HEAD | wc -w)
      if [ "$COLLAB_HEAD_PARENTS" = "2" ]; then
        pass "apr pull --rebase keeps a linear local maintainer commit"
      else
        fail "apr pull --rebase should leave a linear head, got $COLLAB_HEAD_PARENTS fields"
        git -C "$COLLAB_DIR" log --oneline --graph -5
      fi

      $APR --json push --registry collab-reg --branch "$DEFAULT_BRANCH" \
        > /tmp/branch-collab-push.json 2>&1 || {
        cat /tmp/branch-collab-push.json
        fail "second maintainer pushes rebased package"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "push"
          and .branch == $default
          and .set_upstream == false
          and .force == false
          and .current == $default
          and (.head | length == 64)' \
        /tmp/branch-collab-push.json >/dev/null || {
        cat /tmp/branch-collab-push.json
        fail "apr --json push reports rebased package push"
      }
      pass "apr --json push reports rebased package push"
      $APR --json pull --registry test-reg > /tmp/branch-primary-pull.json 2>&1 || {
        cat /tmp/branch-primary-pull.json
        fail "first maintainer pulls collaborator package"
      }
      ${pkgs.jq}/bin/jq -e --arg default "$DEFAULT_BRANCH" \
        '.action == "pull"
          and .rebase == false
          and .current == $default
          and (.head | length == 64)
          and (.output | contains("Fast-forward"))' \
        /tmp/branch-primary-pull.json >/dev/null || {
        cat /tmp/branch-primary-pull.json
        fail "apr --json pull reports collaborator package import"
      }
      pass "apr --json pull reports collaborator package import"
      $APR show collab-local --registry test-reg \
        > /tmp/branch-primary-show-collab.out 2>&1 || {
        cat /tmp/branch-primary-show-collab.out
        fail "first maintainer sees collaborator package after pull"
      }
      assert_file_contains /tmp/branch-primary-show-collab.out \
        "Local collaborator package before rebase" \
        "plain apr pull imports collaborator package metadata"
      $APR verify --registry test-reg > /tmp/branch-primary-verify-pulled.out 2>&1 || {
        cat /tmp/branch-primary-verify-pulled.out
        fail "first maintainer registry verifies after pull"
      }
      assert_file_contains /tmp/branch-primary-verify-pulled.out "no errors" \
        "first maintainer registry remains valid after pull"

      check_fail
    '';
  };
}
