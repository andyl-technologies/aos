//! `TreeWalk` methods (forge_git), split from the parent for the §2 line cap.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn fetch_tree_forge_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        input_type: &[u8],
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.validate_fetch_tree_attrs(
            id,
            span,
            value,
            &[
                TYPE_ATTR,
                OWNER_ATTR,
                REPO_ATTR,
                REF_ATTR,
                REV_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                HOST_ATTR,
                b"treeHash",
                DIR_ATTR,
            ],
        )?;

        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(input_type.to_vec()),
        );
        let owner_value = self.required_attr_value_by_name(id, value, OWNER_ATTR, span)?;
        let owner_value = self.force_value(id, span, owner_value)?;
        attrs.insert(
            OWNER_ATTR.to_vec(),
            FlakeRefAttrValue::String(self.context_free_string_bytes(
                id,
                span,
                owner_value,
                "fetchTree",
            )?),
        );
        let repo_value = self.required_attr_value_by_name(id, value, REPO_ATTR, span)?;
        let repo_value = self.force_value(id, span, repo_value)?;
        attrs.insert(
            REPO_ATTR.to_vec(),
            FlakeRefAttrValue::String(self.context_free_string_bytes(
                id,
                span,
                repo_value,
                "fetchTree",
            )?),
        );
        if let Some(reference) = self.optional_fetch_tree_string_attr(id, span, value, REF_ATTR)? {
            attrs.insert(REF_ATTR.to_vec(), FlakeRefAttrValue::String(reference));
        }
        if let Some(rev) = self.optional_fetch_tree_string_attr(id, span, value, REV_ATTR)? {
            attrs.insert(REV_ATTR.to_vec(), FlakeRefAttrValue::String(rev));
        }
        if let Some(nar_hash) =
            self.optional_fetch_tree_string_attr(id, span, value, NAR_HASH_ATTR)?
        {
            attrs.insert(NAR_HASH_ATTR.to_vec(), FlakeRefAttrValue::String(nar_hash));
        }
        if let Some(last_modified) =
            self.optional_fetch_tree_int_attr(id, span, value, LAST_MODIFIED_ATTR)?
        {
            let last_modified = u64::try_from(last_modified).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FetchTree {
                        id,
                        input: LAST_MODIFIED_ATTR.to_vec(),
                        message: "fetchTree integer attribute must be non-negative".to_owned(),
                    },
                    span,
                )
            })?;
            attrs.insert(
                LAST_MODIFIED_ATTR.to_vec(),
                FlakeRefAttrValue::Int(last_modified),
            );
        }
        if let Some(host) = self.optional_fetch_tree_string_attr(id, span, value, HOST_ATTR)? {
            attrs.insert(HOST_ATTR.to_vec(), FlakeRefAttrValue::String(host));
        }
        if let Some(dir) = self.optional_fetch_tree_string_attr(id, span, value, DIR_ATTR)? {
            attrs.insert(DIR_ATTR.to_vec(), FlakeRefAttrValue::String(dir));
        }

        self.fetch_tree_forge_flake_ref_arguments(id, span, input_type, &attrs)
    }

    pub(in crate::eval::tree_walk) fn fetch_tree_git_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.validate_fetch_tree_attrs(
            id,
            span,
            value,
            &[
                TYPE_ATTR,
                URL_ATTR,
                REF_ATTR,
                REV_ATTR,
                SHALLOW_ATTR,
                SUBMODULES_ATTR,
                ALL_REFS_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_COUNT_ATTR,
                EXPORT_IGNORE_ATTR,
                DIRTY_REV_ATTR,
                DIRTY_SHORT_REV_ATTR,
                VERIFY_COMMIT_ATTR,
                KEYTYPE_ATTR,
                PUBLIC_KEY_ATTR,
                PUBLIC_KEYS_ATTR,
                DIR_ATTR,
            ],
        )?;
        let raw_url = self.required_fetch_tree_url(id, span, value)?;
        let dir = self.optional_fetch_tree_string_attr(id, span, value, DIR_ATTR)?;
        let (url, transport_url) =
            Self::fetch_tree_url_with_dir_metadata(id, span, &raw_url, dir.as_deref())?;
        let rev = self.optional_fetch_tree_string_attr(id, span, value, REV_ATTR)?;
        let reference = self.optional_fetch_tree_string_attr(id, span, value, REF_ATTR)?;
        let submodules =
            self.optional_fetch_tree_bool_attr(id, span, value, SUBMODULES_ATTR, false)?;
        let shallow = self.optional_fetch_tree_bool_attr(id, span, value, SHALLOW_ATTR, true)?;
        let all_refs = self.optional_fetch_tree_bool_attr(id, span, value, ALL_REFS_ATTR, false)?;
        let export_ignore =
            self.optional_fetch_tree_bool_attr(id, span, value, EXPORT_IGNORE_ATTR, !submodules)?;
        let dirty_rev = self.optional_fetch_tree_string_attr(id, span, value, DIRTY_REV_ATTR)?;
        let dirty_short_rev =
            self.optional_fetch_tree_string_attr(id, span, value, DIRTY_SHORT_REV_ATTR)?;
        if dirty_rev.is_some() != dirty_short_rev.is_some() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: DIRTY_REV_ATTR.to_vec(),
                    message: "fetchTree git dirtyRev and dirtyShortRev must be provided together"
                        .to_owned(),
                },
                span,
            ));
        }
        let extra_query = self.fetch_tree_git_verified_fetch_query(id, span, value)?;
        let expected_nar_hash = self.optional_fetch_tree_nar_hash_attr(id, span, value)?;
        let expected_last_modified =
            self.optional_fetch_tree_int_attr(id, span, value, LAST_MODIFIED_ATTR)?;
        let expected_rev_count =
            self.optional_fetch_tree_usize_attr(id, span, value, REV_COUNT_ATTR)?;

        Ok(FetchTreeArguments::Git {
            args: FetchGitArguments {
                url,
                transport_url: dir.as_ref().map(|_| transport_url),
                name: "source".to_owned(),
                rev,
                reference,
                submodules,
                shallow,
                all_refs,
                export_ignore,
                extra_query,
            },
            dir,
            expected_nar_hash,
            expected_last_modified,
            expected_rev_count,
            dirty_rev,
            dirty_short_rev,
        })
    }
}
