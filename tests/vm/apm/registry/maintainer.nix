# Registry VM checks for maintainer workflows.
{
  testing,
  pkgs,
  fixtures,
  maintainerWorkflowDeps,
  setupNixPublishEnv,
  maintRunnerDepTool,
  maintRunnerTool,
}: {
  # -------------------------------------------------------------------------
  # registry-maintainer-workflow — Real release, cache, install, execute
  # -------------------------------------------------------------------------
  registry-maintainer-workflow = testing.mkVMTest {
    name = "apm-registry-maintainer-workflow";
    rootfsDeps =
      maintainerWorkflowDeps
      ++ [
        pkgs.jq
        maintRunnerDepTool
        maintRunnerTool
      ];
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: full registry maintainer release and consumer install"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      GIT_STORE="${pkgs.git}"
      CURL_STORE="${pkgs.curl}"
      GIT_HASH=$(basename "$GIT_STORE" | cut -d- -f1)
      CURL_HASH=$(basename "$CURL_STORE" | cut -d- -f1)
      RUNNER_STORE="${maintRunnerTool}"
      RUNNER_DEP_STORE="${maintRunnerDepTool}"
      RUNNER_HASH=$(basename "$RUNNER_STORE" | cut -d- -f1)
      RUNNER_DEP_HASH=$(basename "$RUNNER_DEP_STORE" | cut -d- -f1)
      nix-store -q --references "$RUNNER_STORE" > /tmp/maint-runner-refs.out
      assert_file_contains /tmp/maint-runner-refs.out "$RUNNER_DEP_STORE" \
        "maint-runner root has a real dependency closure"

      # Maintainer creates a local registry and prepares a grouped release branch.
      $APR create maint-reg
      REG_DIR="$REG_STORAGE/maint-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR branch create release-2026q2 --registry maint-reg
      $APR branch switch release-2026q2 --registry maint-reg

      $APR publish "$GIT_STORE" \
        --name maint-git \
        --version 1.0.0 \
        --description "Git from the maintainer workflow" \
        --homepage "https://git-scm.com" \
        --license GPL-2.0-only \
        --maintainer release@example.invalid \
        --registry maint-reg \
        --no-commit
      $APR publish "$CURL_STORE" \
        --name maint-curl \
        --version 1.0.0 \
        --description "Curl from the maintainer workflow" \
        --homepage "https://curl.se" \
        --license curl \
        --maintainer release@example.invalid \
        --registry maint-reg \
        --no-commit
      $APR publish "$RUNNER_STORE" \
        --name maint-runner \
        --version 1.0.0 \
        --description "Executable payload from the maintainer workflow" \
        --license MIT \
        --maintainer release@example.invalid \
        --registry maint-reg \
        --no-commit

      $APR cache generate \
        --registry maint-reg \
        --output /tmp/maint-cache \
        --cache-url http://127.0.0.1:18082 \
        --priority 41 \
        --no-commit

      $APR status --registry maint-reg > /tmp/maint-status.out 2>&1 || {
        cat /tmp/maint-status.out
        fail "apr status reports pending maintainer changes"
      }
      cat /tmp/maint-status.out
      assert_file_contains /tmp/maint-status.out "packages/m/maint-git.toml" \
        "apr status shows git package metadata"
      assert_file_contains /tmp/maint-status.out "packages/m/maint-curl.toml" \
        "apr status shows curl package metadata"
      assert_file_contains /tmp/maint-status.out "packages/m/maint-runner.toml" \
        "apr status shows runner package metadata"
      assert_file_contains /tmp/maint-status.out "registry.toml" \
        "apr status shows cache pointer update"
      $APR --json status --registry maint-reg > /tmp/maint-status.json 2>&1 || {
        cat /tmp/maint-status.json
        fail "apr --json status reports pending maintainer changes"
      }
      ${pkgs.jq}/bin/jq -e \
        '.clean == false
          and (.entries | any(.path == "packages/m/maint-git.toml"))
          and (.entries | any(.path == "packages/m/maint-curl.toml"))
          and (.entries | any(.path == "packages/m/maint-runner.toml"))
          and (.entries | any(.path == "registry.toml"))' \
        /tmp/maint-status.json >/dev/null || {
        cat /tmp/maint-status.json
        fail "apr --json status reports real changeset paths"
      }
      pass "apr --json status reports real changeset paths"

      $APR diff --registry maint-reg --stat > /tmp/maint-diff-stat.out 2>&1 || {
        cat /tmp/maint-diff-stat.out
        fail "apr diff --stat reports tracked maintainer changes"
      }
      cat /tmp/maint-diff-stat.out
      assert_file_contains /tmp/maint-diff-stat.out "registry.toml" \
        "apr diff --stat shows tracked cache pointer update"
      assert_file_contains /tmp/maint-diff-stat.out "packages/m/maint-git.toml" \
        "apr diff --stat shows untracked git package metadata"
      assert_file_contains /tmp/maint-diff-stat.out "packages/m/maint-curl.toml" \
        "apr diff --stat shows untracked curl package metadata"
      assert_file_contains /tmp/maint-diff-stat.out "packages/m/maint-runner.toml" \
        "apr diff --stat shows untracked runner package metadata"
      $APR --json diff --registry maint-reg --stat \
        > /tmp/maint-diff-stat.json 2>&1 || {
        cat /tmp/maint-diff-stat.json
        fail "apr --json diff --stat reports tracked maintainer changes"
      }
      ${pkgs.jq}/bin/jq -e \
        '.remote == false
          and .stat == true
          and .clean == false
          and (.changed_files | any(.status == "M" and .path == "registry.toml"))
          and (.changed_files | any(.status == "A" and .path == "packages/m/maint-git.toml" and .untracked == true))
          and (.changed_files | any(.status == "A" and .path == "packages/m/maint-curl.toml" and .untracked == true))
          and (.changed_files | any(.status == "A" and .path == "packages/m/maint-runner.toml" and .untracked == true))
          and (.output | contains("registry.toml"))
          and (.output | contains("packages/m/maint-git.toml"))
          and (.output | contains("packages/m/maint-curl.toml"))
          and (.output | contains("packages/m/maint-runner.toml"))' \
        /tmp/maint-diff-stat.json >/dev/null || {
        cat /tmp/maint-diff-stat.json
        fail "apr --json diff --stat reports full maintainer changeset"
      }
      pass "apr --json diff --stat reports full maintainer changeset"

      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/changeset.status
      cat /tmp/changeset.status
      assert_file_contains /tmp/changeset.status "packages/m/maint-git.toml" \
        "changeset includes git package metadata"
      assert_file_contains /tmp/changeset.status "packages/m/maint-curl.toml" \
        "changeset includes curl package metadata"
      assert_file_contains /tmp/changeset.status "packages/m/maint-runner.toml" \
        "changeset includes runner package metadata"
      assert_file_contains /tmp/changeset.status "registry.toml" \
        "changeset includes cache pointer update"
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$GIT_HASH")/$GIT_HASH" \
        "changeset includes git store record"
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$CURL_HASH")/$CURL_HASH" \
        "changeset includes curl store record"
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$RUNNER_HASH")/$RUNNER_HASH" \
        "changeset includes runner store record"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: publish maintainer tools"
      git -C "$REG_DIR" diff --name-only "$DEFAULT_BRANCH"..HEAD > /tmp/changeset.files
      cat /tmp/changeset.files
      assert_file_contains /tmp/changeset.files "packages/m/maint-git.toml" \
        "release diff carries git package"
      assert_file_contains /tmp/changeset.files "packages/m/maint-curl.toml" \
        "release diff carries curl package"
      assert_file_contains /tmp/changeset.files "packages/m/maint-runner.toml" \
        "release diff carries runner package"
      assert_file_contains /tmp/changeset.files "registry.toml" \
        "release diff carries cache endpoint"
      $APR log --registry maint-reg --package maint-runner -n 1 \
        > /tmp/maint-log-runner.out 2>&1 || {
        cat /tmp/maint-log-runner.out
        fail "apr log --package reports package history"
      }
      cat /tmp/maint-log-runner.out
      assert_file_contains /tmp/maint-log-runner.out \
        "release: publish maintainer tools" \
        "apr log --package shows maintainer package commit"
      $APR --json log --registry maint-reg --package maint-runner -n 1 \
        > /tmp/maint-log-runner.json 2>&1 || {
        cat /tmp/maint-log-runner.json
        fail "apr --json log --package reports package history"
      }
      ${pkgs.jq}/bin/jq -e \
        '.package == "maint-runner"
          and .limit == 1
          and (.commits | length == 1)
          and .commits[0].subject == "release: publish maintainer tools"
          and (.commits[0].hash | length > 0)
          and (.commits[0].short_hash | length > 0)
          and (.commits[0].timestamp > 0)' \
        /tmp/maint-log-runner.json >/dev/null || {
        cat /tmp/maint-log-runner.json
        fail "apr --json log --package reports maintainer package commit"
      }
      pass "apr --json log --package reports maintainer package commit"

      $APR packages --registry maint-reg > /tmp/maint-packages.out 2>&1
      assert_file_contains /tmp/maint-packages.out "maint-git" \
        "apr packages lists git"
      assert_file_contains /tmp/maint-packages.out "maint-curl" \
        "apr packages lists curl"
      assert_file_contains /tmp/maint-packages.out "maint-runner" \
        "apr packages lists runner"
      $APR verify --registry maint-reg

      $APR branch switch "$DEFAULT_BRANCH" --registry maint-reg
      $APR merge release-2026q2 --registry maint-reg
      ssh-keygen -q -t ed25519 -N "" -f /tmp/maint-release-key

      $APR --json release 1.0.0 \
        --registry maint-reg \
        --key /tmp/maint-release-key \
        --cache-url http://127.0.0.1:18084 \
        --channel stable \
        --init-channel \
        --upload-url file:///tmp/maint-origin-dry-run \
        --dry-run \
        > /tmp/release-dry-run.json 2>&1 || {
        cat /tmp/release-dry-run.json
        fail "apr release --dry-run plans full maintainer release"
      }
      ${pkgs.jq}/bin/jq -e \
        '.action == "release"
          and .status == "planned"
          and .registry == "maint-reg"
          and .version == "1.0.0"
          and .dry_run == true
          and .cache_url == "http://127.0.0.1:18084"
          and (.cache_dir | endswith("/apm/registry-static/maint-reg"))
          and .upload_urls == ["file:///tmp/maint-origin-dry-run"]
          and .channel.name == "stable"
          and .channel.action == "init"
          and .channel.touched_partitions == null
          and .cache == null
          and .full_pack == null
          and .deltas == []
          and (.planned_steps | index("commit_cache_pointer") != null)
          and (.planned_steps | index("generate_static_cache") != null)
          and (.planned_steps | index("initialize_channel") != null)
          and (.planned_steps | index("upload_static_origin") != null)' \
        /tmp/release-dry-run.json >/dev/null || {
        cat /tmp/release-dry-run.json
        fail "apr --json release --dry-run reports full release plan"
      }
      pass "apr --json release --dry-run reports full release plan"
      if git -C "$REG_DIR" rev-parse "1.0.0^{tag}" >/tmp/release-dry-run-tag.out 2>&1; then
        cat /tmp/release-dry-run-tag.out
        fail "release dry-run should not create release tag"
      else
        pass "release dry-run does not create release tag"
      fi
      if [ -e "$REG_DIR/.git/releases/1/0/0" ]; then
        fail "release dry-run should not write release pack artifacts"
      else
        pass "release dry-run does not write release pack artifacts"
      fi
      if [ -e /tmp/maint-release-cache-dry-run ]; then
        fail "release dry-run should not generate static cache output"
      else
        pass "release dry-run does not generate static cache output"
      fi
      if [ -e /tmp/maint-origin-dry-run ]; then
        fail "release dry-run should not upload static origin files"
      else
        pass "release dry-run does not upload static origin files"
      fi
      if grep -q "http://127.0.0.1:18084" "$REG_DIR/registry.toml"; then
        fail "release dry-run should not mutate registry cache pointer"
      else
        pass "release dry-run leaves registry cache pointer unchanged"
      fi
      if git -C "$REG_DIR" status --short --untracked-files=all | grep -q .; then
        git -C "$REG_DIR" status --short --untracked-files=all
        fail "release dry-run should leave worktree clean"
      else
        pass "release dry-run leaves worktree clean"
      fi

      echo "dirty maintainer scratch note" > "$REG_DIR/maintainer-notes.txt"
      if $APR release 1.0.0 \
        --registry maint-reg \
        --key /tmp/maint-release-key \
        --cache-url http://127.0.0.1:18083 \
        --upload-url file:///tmp/maint-cache \
        > /tmp/dirty-release.out 2>&1; then
        cat /tmp/dirty-release.out
        fail "apr release should refuse dirty registry before cache pointer commit"
      else
        cat /tmp/dirty-release.out
        assert_file_contains /tmp/dirty-release.out "uncommitted changes" \
          "apr release refuses dirty registry"
        if git -C "$REG_DIR" log --oneline -1 | grep -q "registry: update static cache pointer"; then
          fail "dirty release should not commit cache pointer"
        else
          pass "dirty release does not commit cache pointer"
        fi
        if git -C "$REG_DIR" ls-tree -r --name-only HEAD | grep -q "maintainer-notes.txt"; then
          fail "dirty release should not sweep unrelated files into HEAD"
        else
          pass "dirty release does not commit unrelated dirty file"
        fi
        if grep -q "http://127.0.0.1:18083" "$REG_DIR/registry.toml"; then
          fail "dirty release should not mutate registry cache pointer"
        else
          pass "dirty release leaves registry cache pointer unchanged"
        fi
      fi
      rm -f "$REG_DIR/maintainer-notes.txt"

      $APR --json release 1.0.0 \
        --registry maint-reg \
        --key /tmp/maint-release-key \
        --cache-url http://127.0.0.1:18082 \
        --upload-url file:///tmp/maint-cache \
        > /tmp/release.json 2>&1 || {
        cat /tmp/release.json
        fail "apr release signs merged release"
      }
      ${pkgs.jq}/bin/jq -e \
        '.action == "release"
          and .status == "released"
          and .registry == "maint-reg"
          and .version == "1.0.0"
          and .dry_run == false
          and .cache_url == "http://127.0.0.1:18082"
          and .cache_pointer_updated == false
          and (.full_pack | startswith("pack-") and endswith(".pack"))
          and .deltas == []
          and (.cache.paths >= 3)
          and (.uploaded_files > 0)' \
        /tmp/release.json >/dev/null || {
        cat /tmp/release.json
        fail "apr --json release reports signed maintainer release"
      }
      pass "apr --json release reports signed maintainer release"
      if git -C "$REG_DIR" rev-parse "1.0.0^{tag}" >/tmp/release-tag.out 2>&1; then
        pass "apr release creates annotated tag object"
      else
        cat /tmp/release-tag.out
        fail "apr release should create annotated tag object"
      fi
      assert_file_contains "$REG_DIR/.git/releases/1/0/0/objects/info/packs" \
        "pack-" "apr release records full pack artifact"

      git init --bare --object-format=sha256 /tmp/maint-origin.git
      git -C "$REG_DIR" remote add origin /tmp/maint-origin.git
      $APR push --registry maint-reg --branch "$DEFAULT_BRANCH" \
        > /tmp/maint-push.out 2>&1 || {
        cat /tmp/maint-push.out
        fail "apr push publishes default branch"
      }
      cat /tmp/maint-push.out
      assert_file_contains /tmp/maint-push.out "Pushed." \
        "apr push reports successful branch push"
      $APR diff --registry maint-reg --remote --stat \
        > /tmp/maint-remote-diff.out 2>&1 || {
        cat /tmp/maint-remote-diff.out
        fail "apr diff --remote compares against pushed branch"
      }
      cat /tmp/maint-remote-diff.out
      assert_file_contains /tmp/maint-remote-diff.out "No pending changes" \
        "apr diff --remote is clean after pushing branch"
      $APR --json diff --registry maint-reg --remote --stat \
        > /tmp/maint-remote-diff.json 2>&1 || {
        cat /tmp/maint-remote-diff.json
        fail "apr --json diff --remote compares against pushed branch"
      }
      ${pkgs.jq}/bin/jq -e \
        '.remote == true
          and .stat == true
          and .clean == true
          and (.changed_files | length == 0)
          and (.base | length > 0)
          and (.output | contains("0 files changed"))' \
        /tmp/maint-remote-diff.json >/dev/null || {
        cat /tmp/maint-remote-diff.json
        fail "apr --json diff --remote is clean after pushing branch"
      }
      pass "apr --json diff --remote is clean after pushing branch"
      git -C "$REG_DIR" push origin 1.0.0

      assert_file_exists "/tmp/maint-cache/$GIT_HASH.narinfo" \
        "static cache contains git narinfo"
      assert_file_exists "/tmp/maint-cache/$CURL_HASH.narinfo" \
        "static cache contains curl narinfo"
      assert_file_exists "/tmp/maint-cache/$RUNNER_HASH.narinfo" \
        "static cache contains runner narinfo"
      assert_file_exists "/tmp/maint-cache/$RUNNER_DEP_HASH.narinfo" \
        "static cache contains runner dependency narinfo"
      assert_dir_exists /tmp/maint-cache/nar \
        "static cache contains NAR directory"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18082 --bind 127.0.0.1 \
        --directory /tmp/maint-cache > /tmp/maint-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18082/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if ! curl -sf http://127.0.0.1:18082/nix-cache-info >/dev/null; then
        cat /tmp/maint-cache-http.log || true
        fail "static cache HTTP server started"
      else
        pass "static cache HTTP server started"
      fi
      curl -sf "http://127.0.0.1:18082/$RUNNER_HASH.narinfo" > /tmp/runner.narinfo
      assert_file_contains /tmp/runner.narinfo "URL: nar/" \
        "consumer can fetch runner narinfo over HTTP"

      $APR validate --registry maint-reg --jobs 4 \
        > /tmp/maint-validate.out 2>&1 || {
        cat /tmp/maint-validate.out
        fail "apr validate confirms generated cache contents"
      }
      cat /tmp/maint-validate.out
      assert_file_contains /tmp/maint-validate.out "All 3 entries found in caches" \
        "apr validate checks every published cache entry"
      $APR --json validate --registry maint-reg --jobs 4 \
        > /tmp/maint-validate.json 2>&1 || {
        cat /tmp/maint-validate.json
        fail "apr --json validate confirms generated cache contents"
      }
      ${pkgs.jq}/bin/jq -e \
        '.status == "ok"
          and .fix == false
          and .jobs == 4
          and .caches == 1
          and .checked == 3
          and .found == 3
          and .missing == 0
          and .removed == 0
          and .missing_entries == []' \
        /tmp/maint-validate.json >/dev/null || {
        cat /tmp/maint-validate.json
        fail "apr --json validate reports generated cache contents"
      }
      pass "apr --json validate reports generated cache contents"
      $APR validate --registry maint-reg \
        --package maint-runner \
        --platform x86_64-linux \
        --jobs 2 > /tmp/maint-validate-runner.out 2>&1 || {
        cat /tmp/maint-validate-runner.out
        fail "apr validate filtered to one package succeeds"
      }
      assert_file_contains /tmp/maint-validate-runner.out "All 1 entries found in caches" \
        "apr validate honors package and platform filters"
      $APR --json validate --registry maint-reg \
        --package maint-runner \
        --platform x86_64-linux \
        --jobs 2 > /tmp/maint-validate-runner.json 2>&1 || {
        cat /tmp/maint-validate-runner.json
        fail "apr --json validate filtered to one package succeeds"
      }
      ${pkgs.jq}/bin/jq -e \
        '.status == "ok"
          and .package == "maint-runner"
          and .platform == "x86_64-linux"
          and .checked == 1
          and .found == 1
          and .missing == 0' \
        /tmp/maint-validate-runner.json >/dev/null || {
        cat /tmp/maint-validate-runner.json
        fail "apr --json validate honors package and platform filters"
      }
      pass "apr --json validate honors package and platform filters"
      if $APR validate --registry maint-reg --jobs 0 \
        > /tmp/maint-validate-jobs-zero.out 2>&1; then
        cat /tmp/maint-validate-jobs-zero.out
        fail "apr validate should reject zero parallelism"
      else
        assert_file_contains /tmp/maint-validate-jobs-zero.out \
          "jobs must be greater than zero" \
          "apr validate rejects zero parallelism"
      fi

      rm -f "/tmp/maint-cache/$CURL_HASH.narinfo"
      if $APR validate --registry maint-reg --package maint-curl --jobs 1 \
        > /tmp/maint-validate-missing-curl.out 2>&1; then
        cat /tmp/maint-validate-missing-curl.out
        fail "apr validate should fail when a cache entry is missing"
      else
        cat /tmp/maint-validate-missing-curl.out
        assert_file_contains /tmp/maint-validate-missing-curl.out \
          "not found in any cache" \
          "apr validate reports the missing cache entry before fix"
      fi
      if $APR --json validate --registry maint-reg --package maint-curl --jobs 1 \
        > /tmp/maint-validate-missing-curl.json 2>&1; then
        cat /tmp/maint-validate-missing-curl.json
        fail "apr --json validate should fail when a cache entry is missing"
      else
        ${pkgs.jq}/bin/jq -e --arg store "$CURL_STORE" \
          '.error
            | contains("0 found, 1 missing")
            and contains("maint-curl")
            and contains($store)' \
          /tmp/maint-validate-missing-curl.json >/dev/null || {
          cat /tmp/maint-validate-missing-curl.json
          fail "apr --json validate reports the missing cache entry before fix"
        }
        pass "apr --json validate reports the missing cache entry before fix"
      fi
      $APR --json validate --registry maint-reg --package maint-curl --jobs 1 --fix \
        > /tmp/maint-validate-fix-curl.json 2>&1 || {
        cat /tmp/maint-validate-fix-curl.json
        fail "apr validate --fix prunes missing cache entry metadata"
      }
      ${pkgs.jq}/bin/jq -e --arg store "$CURL_STORE" \
        '.status == "fixed"
          and .package == "maint-curl"
          and .fix == true
          and .checked == 1
          and .found == 0
          and .missing == 1
          and .removed == 1
          and (.missing_entries | length == 1)
          and .missing_entries[0].name == "maint-curl"
          and .missing_entries[0].store_path == $store
          and (.missing_entries[0].details | length > 0)' \
        /tmp/maint-validate-fix-curl.json >/dev/null || {
        cat /tmp/maint-validate-fix-curl.json
        fail "apr --json validate --fix reports pruned missing entry"
      }
      pass "apr --json validate --fix reports pruned missing entry"
      assert_file_not_exists "$REG_DIR/packages/m/maint-curl.toml" \
        "apr validate --fix removes package with no cached versions"
      $APR packages --registry maint-reg \
        > /tmp/maint-packages-after-validate-fix.out 2>&1 || {
        cat /tmp/maint-packages-after-validate-fix.out
        fail "apr packages succeeds after validate --fix"
      }
      assert_file_not_contains /tmp/maint-packages-after-validate-fix.out \
        "maint-curl" \
        "apr packages hides cache-pruned package"
      assert_file_contains /tmp/maint-packages-after-validate-fix.out \
        "maint-runner" \
        "apr packages keeps cache-backed package after validate --fix"
      git -C "$REG_DIR" status --short > /tmp/maint-validate-fix-status.out
      assert_file_contains /tmp/maint-validate-fix-status.out \
        "packages/m/maint-curl.toml" \
        "apr validate --fix leaves a maintainer changeset"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "drop maint-curl missing from cache" \
        > /tmp/maint-validate-fix-commit.out 2>&1 || {
        cat /tmp/maint-validate-fix-commit.out
        fail "maintainer commits validate --fix changeset"
      }
      cat /tmp/maint-validate-fix-commit.out
      $APR verify --registry maint-reg \
        > /tmp/maint-verify-after-validate-fix.out 2>&1 || {
        cat /tmp/maint-verify-after-validate-fix.out
        fail "apr verify accepts registry after validate --fix"
      }
      assert_file_contains /tmp/maint-verify-after-validate-fix.out \
        "no errors" \
        "apr verify validates registry after validate --fix"

      # Consumer uses a fresh HOME and the published git origin.
      export HOME=/tmp/consumer
      export USER=maintconsumer
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/maint-origin.git --name maint-reg --tag 1.0.0
      $APM search maint-runner --registry maint-reg > /tmp/consumer-search.out 2>&1
      assert_file_contains /tmp/consumer-search.out "maint-runner" \
        "consumer registry exposes runner package"
      assert_file_contains "$HOME/.local/share/apm/registries/maint-reg/registry.toml" \
        "http://127.0.0.1:18082" "consumer synced cache endpoint"

      # Force a real download by removing the target package from the VM store.
      mount -o remount,rw / || true
      nix-store --delete --ignore-liveness "$RUNNER_STORE" > /tmp/delete-runner.out 2>&1 || {
        cat /tmp/delete-runner.out
        fail "deleted runner store path before install"
      }
      nix-store --delete --ignore-liveness "$RUNNER_DEP_STORE" > /tmp/delete-runner-dep.out 2>&1 || {
        cat /tmp/delete-runner-dep.out
        fail "deleted runner dependency store path before install"
      }
      if nix-store --check-validity "$RUNNER_STORE" >/tmp/runner-valid.out 2>&1; then
        cat /tmp/runner-valid.out
        fail "runner store path should be missing before install"
      else
        pass "runner store path missing before install"
      fi
      if nix-store --check-validity "$RUNNER_DEP_STORE" >/tmp/runner-dep-valid.out 2>&1; then
        cat /tmp/runner-dep-valid.out
        fail "runner dependency store path should be missing before install"
      else
        pass "runner dependency store path missing before install"
      fi

      $APM install maint-runner --registry maint-reg --yes > /tmp/install-runner.out 2>&1 || {
        cat /tmp/install-runner.out
        fail "apm install downloads and imports runner"
      }
      cat /tmp/install-runner.out
      assert_file_contains /tmp/install-runner.out "Downloading 2 NAR" \
        "apm install downloaded runner closure"
      assert_file_contains /tmp/install-runner.out "Installed 1 package" \
        "apm install completed profile update"
      if find "$HOME/.cache/apm" -name '*.nar.zst' | grep -q .; then
        pass "downloaded NAR retained in user cache"
      else
        fail "downloaded NAR retained in user cache"
      fi
      nix-store --check-validity "$RUNNER_STORE" >/tmp/runner-valid-after.out 2>&1
      nix-store --check-validity "$RUNNER_DEP_STORE" >/tmp/runner-dep-valid-after.out 2>&1

      PROFILE_RUNNER="/var/lib/profiles/per-user/$USER/current/bin/maint-runner"
      if [ -x "$PROFILE_RUNNER" ]; then
        pass "installed profile exposes runner executable"
      else
        fail "installed profile exposes runner executable"
      fi
      "$PROFILE_RUNNER" > /tmp/profile-runner.out
      assert_file_contains /tmp/profile-runner.out \
        "^maint-runner 1.0.0 via maint-runner-dep 1.0.0$" \
        "installed runner executes from profile through dependency"
      $APM files maint-runner > /tmp/maint-runner-files.out 2>&1 || {
        cat /tmp/maint-runner-files.out
        fail "apm files lists installed maintainer package"
      }
      cat /tmp/maint-runner-files.out
      assert_file_contains /tmp/maint-runner-files.out "bin/maint-runner" \
        "apm files lists installed executable"
      assert_file_contains /tmp/maint-runner-files.out "bin/maint-runner-link" \
        "apm files lists file symlink without resolving it"
      assert_file_contains /tmp/maint-runner-files.out "share/maint-runner/payload.bin" \
        "apm files lists large payload"
      assert_file_contains /tmp/maint-runner-files.out "share/maint-runner/current" \
        "apm files lists directory symlink without recursing"
      assert_file_not_contains /tmp/maint-runner-files.out "current/current" \
        "apm files does not recurse through directory symlink loop"
      $APM list > /tmp/apm-list.out 2>&1
      assert_file_contains /tmp/apm-list.out "maint-runner" \
        "apm list shows installed maintainer package"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
