//! Detached 9p request execution and visibility-aware reply generation.

use super::*;

/// The detached COMPUTE view a [`NinepDevice`] hands to [`IoCore::process_inbox`].
///
/// Borrows only the device fields the COMPUTE step touches (the server and the
/// latency model), sidestepping the `&mut self`-to-both-args borrow conflict. It
/// is the concrete [`IoSubNode`]: every request frame is dispatched through the
/// [`NinepServer`], which answers malformed/mutating/unknown messages with an
/// `Rlerror` frame, never a panic ([IO-17], [IO-18]).
pub(super) struct NinepServerNode<'a> {
    pub(super) server: &'a mut NinepServer,
    pub(super) latency: &'a NinepLatency,
    pub(super) require_fault_directives: bool,
    pub(super) directives: &'a mut BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
    pub(super) visibility: &'a NinepVisibilityState,
    pub(super) virtual_fids: &'a mut BTreeMap<u32, NinepVirtualFid>,
    pub(super) session_epoch: &'a mut u64,
}

impl<'a> IoSubNode for NinepServerNode<'a> {
    type Latency = NinepLatency;
    type ComputeCheckpoint = (NinepServer, BTreeMap<u32, NinepVirtualFid>, u64);

    fn latency_model(&self) -> &Self::Latency {
        self.latency
    }

    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint {
        (
            self.server.clone(),
            self.virtual_fids.clone(),
            *self.session_epoch,
        )
    }

    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint) {
        *self.server = checkpoint.0;
        *self.virtual_fids = checkpoint.1;
        *self.session_epoch = checkpoint.2;
    }

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        let message = Message::decode(&request.payload).ok();
        let begins_session = message
            .as_ref()
            .is_some_and(|message| matches!(message.body, TMessage::Version { .. }));
        if begins_session && *self.session_epoch == u64::MAX {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p session epoch overflow",
            });
        }
        let identity = ResolvedNinepRequestDirective::fault_free(
            request.request_icount,
            request.request_id,
            &request.payload,
        )?
        .identity;
        let directive = self.directives.get(&identity).cloned();
        if self.require_fault_directives && directive.is_none() {
            return Err(DeviceError::MissingNinepFaultDirective { tag: identity.tag });
        }
        if let Some(directive) = &directive {
            directive.validate_for(request.request_icount, request.request_id, &request.payload)?;
        }

        let reply = match directive.as_ref().map(|directive| &directive.result) {
            Some(NinepResultDirective::Errno(errno)) => {
                codec::encode_rlerror(identity.tag, *errno)?
            }
            Some(NinepResultDirective::Stale(object))
            | Some(NinepResultDirective::Misdirected(object)) => object_reply(
                message
                    .as_ref()
                    .ok_or(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p object result requires a decodable request",
                    })?,
                object,
                NinepVirtualFid::Exact(object.clone()),
                self.virtual_fids,
            )?,
            Some(NinepResultDirective::Normal) | None => {
                let layered = message
                    .as_ref()
                    .map(|message| {
                        visibility_reply(
                            message,
                            self.server,
                            self.visibility,
                            *self.session_epoch,
                            self.virtual_fids,
                        )
                    })
                    .transpose()?
                    .flatten();
                if let Some(reply) = layered {
                    reply
                } else {
                    let reply = self.server.handle(&request.payload)?;
                    if let Some(message) = &message {
                        match message.body {
                            TMessage::Version { .. } => self.virtual_fids.clear(),
                            TMessage::Clunk { fid } => {
                                self.virtual_fids.remove(&fid);
                            }
                            _ => {}
                        }
                    }
                    reply
                }
            }
        };
        if directive.is_some() {
            self.directives.remove(&identity);
        }
        if begins_session {
            *self.session_epoch += 1;
        }
        // The status is Ok unless the reply is an Rlerror frame; map the 9p
        // reply type byte (offset 4) to the uniform status so the core's
        // coincident-delivery ordering and any fault hooks see the outcome.
        let status = match reply.get(4) {
            Some(&codec::RLERROR) => ResponseStatus::Error,
            _ => ResponseStatus::Ok,
        };
        Ok(ComputedResponse::primary(Response::new(
            request.request_id,
            status,
            reply,
        )))
    }
}

pub(super) fn request_fid(message: &TMessage) -> Option<u32> {
    match message {
        TMessage::Walk { fid, .. }
        | TMessage::Lopen { fid, .. }
        | TMessage::Read { fid, .. }
        | TMessage::Readdir { fid, .. }
        | TMessage::Getattr { fid, .. }
        | TMessage::Readlink { fid }
        | TMessage::Statfs { fid }
        | TMessage::Clunk { fid }
        | TMessage::Xattrwalk { fid, .. }
        | TMessage::Fsync { fid } => Some(*fid),
        TMessage::Version { .. }
        | TMessage::Attach { .. }
        | TMessage::Flush { .. }
        | TMessage::Mutating { .. }
        | TMessage::Unknown { .. } => None,
    }
}

pub(super) fn canonical_path(components: &[String]) -> String {
    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

pub(super) fn fid_path(
    server: &NinepServer,
    virtual_fids: &BTreeMap<u32, NinepVirtualFid>,
    fid: u32,
) -> Option<String> {
    virtual_fids
        .get(&fid)
        .map(|binding| binding.path().to_owned())
        .or_else(|| {
            server
                .fids()
                .get(&fid)
                .map(|entry| canonical_path(&entry.path))
        })
}

pub(super) fn visibility_reply(
    message: &Message,
    server: &NinepServer,
    visibility: &NinepVisibilityState,
    session: u64,
    virtual_fids: &mut BTreeMap<u32, NinepVirtualFid>,
) -> Result<Option<Vec<u8>>, DeviceError> {
    if let TMessage::Walk {
        fid,
        newfid,
        wnames,
    } = &message.body
    {
        let Some(start) = fid_path(server, virtual_fids, *fid) else {
            return Ok(None);
        };
        let mut components = if start == "/" {
            Vec::new()
        } else {
            start
                .trim_start_matches('/')
                .split('/')
                .map(str::to_owned)
                .collect()
        };
        let mut qids = Vec::new();
        let mut overlay_touched = virtual_fids.contains_key(fid);
        for name in wnames {
            if super::super::tree::validate_component(name).is_err() {
                return Ok(Some(codec::encode_rlerror(
                    message.tag,
                    super::super::errno::EINVAL,
                )?));
            }
            let parent_path = canonical_path(&components);
            let parent_is_directory = match visibility.lookup_object(session, &parent_path) {
                NinepVisibilityLookup::Object(object) => {
                    overlay_touched = true;
                    object.mode & 0o170_000 == 0o040_000
                }
                NinepVisibilityLookup::Deleted => {
                    overlay_touched = true;
                    false
                }
                NinepVisibilityLookup::Base => matches!(
                    server.tree().resolve(&components),
                    Some(Node::Directory { .. })
                ),
            };
            if !parent_is_directory {
                if qids.is_empty() {
                    return Ok(Some(codec::encode_rlerror(
                        message.tag,
                        super::super::errno::ENOTDIR,
                    )?));
                }
                break;
            }
            components.push(name.clone());
            let path = canonical_path(&components);
            match visibility.lookup_object(session, &path) {
                NinepVisibilityLookup::Object(object) => {
                    qids.push(object_qid(&object));
                    overlay_touched = true;
                }
                NinepVisibilityLookup::Deleted => {
                    overlay_touched = true;
                    components.pop();
                    break;
                }
                NinepVisibilityLookup::Base => match server.tree().qid(&components) {
                    Some(qid) => qids.push(qid),
                    None => {
                        components.pop();
                        break;
                    }
                },
            }
        }
        if !overlay_touched {
            return Ok(None);
        }
        if qids.is_empty() && !wnames.is_empty() {
            return Ok(Some(codec::encode_rlerror(
                message.tag,
                super::super::errno::ENOENT,
            )?));
        }
        virtual_fids.insert(
            *newfid,
            NinepVirtualFid::VisiblePath(canonical_path(&components)),
        );
        return Ok(Some(codec::encode_rwalk(message.tag, &qids)?));
    }

    let Some(fid) = request_fid(&message.body) else {
        return Ok(None);
    };
    if virtual_fids.contains_key(&fid) {
        match message.body {
            TMessage::Clunk { .. } => {
                virtual_fids.remove(&fid);
                return Ok(Some(codec::encode_rclunk(message.tag)?));
            }
            TMessage::Fsync { .. } => {
                return Ok(Some(codec::encode_rfsync(message.tag)?));
            }
            TMessage::Statfs { .. } => {
                return Ok(Some(server.tree().statfs().encode(message.tag)?));
            }
            _ => {}
        }
    }
    if let Some(NinepVirtualFid::Exact(object)) = virtual_fids.get(&fid).cloned() {
        return object_reply(
            message,
            &object,
            NinepVirtualFid::Exact(object.clone()),
            virtual_fids,
        )
        .map(Some);
    }
    let Some(path) = fid_path(server, virtual_fids, fid) else {
        return Ok(None);
    };
    match visibility.lookup_object(session, &path) {
        NinepVisibilityLookup::Base => {
            if virtual_fids.contains_key(&fid) {
                Ok(Some(codec::encode_rlerror(
                    message.tag,
                    super::super::errno::ENOENT,
                )?))
            } else {
                Ok(None)
            }
        }
        NinepVisibilityLookup::Deleted => Ok(Some(codec::encode_rlerror(
            message.tag,
            super::super::errno::ENOENT,
        )?)),
        NinepVisibilityLookup::Object(object) => object_reply(
            message,
            &object,
            NinepVirtualFid::VisiblePath(path),
            virtual_fids,
        )
        .map(Some),
    }
}

pub(super) fn object_qid(object: &NinepObjectVersion) -> Qid {
    let kind = match object.mode & 0o170_000 {
        0o040_000 => QidType::Dir,
        0o120_000 => QidType::Symlink,
        _ => QidType::File,
    };
    Qid {
        kind,
        version: object.version,
        path: super::super::tree::qid_path(&object.components()),
    }
}

pub(super) fn object_reply(
    message: &Message,
    object: &NinepObjectVersion,
    binding: NinepVirtualFid,
    virtual_fids: &mut BTreeMap<u32, NinepVirtualFid>,
) -> Result<Vec<u8>, DeviceError> {
    object.validate()?;
    let tag = message.tag;
    if object.deleted {
        return codec::encode_rlerror(tag, super::super::errno::ENOENT).map_err(DeviceError::from);
    }
    let qid = object_qid(object);
    let reply = match &message.body {
        TMessage::Walk { newfid, wnames, .. } => {
            virtual_fids.insert(*newfid, binding.clone());
            let qids = if wnames.is_empty() {
                Vec::new()
            } else {
                vec![qid]
            };
            codec::encode_rwalk(tag, &qids)?
        }
        TMessage::Lopen { fid, .. } => {
            virtual_fids.insert(*fid, binding.clone());
            codec::encode_rlopen(tag, &qid, 0)?
        }
        TMessage::Read { offset, count, .. } => {
            if object.mode & 0o170_000 != 0o100_000 {
                codec::encode_rlerror(
                    tag,
                    if object.mode & 0o170_000 == 0o040_000 {
                        super::super::errno::EISDIR
                    } else {
                        super::super::errno::EINVAL
                    },
                )?
            } else {
                let start = usize::try_from(*offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(*count as usize).min(object.data.len());
                let data = object.data.get(start..end).unwrap_or(&[]);
                codec::encode_rread(tag, data)?
            }
        }
        TMessage::Readdir { offset, count, .. } => {
            if object.mode & 0o170_000 != 0o040_000 {
                codec::encode_rlerror(tag, super::super::errno::ENOTDIR)?
            } else {
                let mut data = Vec::new();
                let entries = [(1_u64, qid, "."), (2_u64, qid, "..")];
                for (cookie, entry_qid, name) in entries {
                    if cookie <= *offset {
                        continue;
                    }
                    let mut encoded = Vec::new();
                    codec::push_dirent(&mut encoded, &entry_qid, cookie, 4, name)?;
                    if data.len().saturating_add(encoded.len()) > *count as usize {
                        if data.is_empty() {
                            return Ok(codec::encode_rlerror(tag, super::super::errno::EMSGSIZE)?);
                        }
                        break;
                    }
                    data.extend_from_slice(&encoded);
                }
                codec::encode_rreaddir(tag, &data)?
            }
        }
        TMessage::Getattr { request_mask, .. } => {
            let size = u64::try_from(object.data.len()).unwrap_or(u64::MAX);
            GetattrReply {
                valid: *request_mask,
                qid,
                mode: object.mode,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
                size,
                blksize: 4096,
                blocks: size.saturating_add(511) / 512,
            }
            .encode(tag)?
        }
        TMessage::Readlink { .. } => {
            if object.mode & 0o170_000 != 0o120_000 {
                codec::encode_rlerror(tag, super::super::errno::EINVAL)?
            } else {
                let target = std::str::from_utf8(&object.data).map_err(|_| {
                    DeviceError::InvalidNinepFaultDirective {
                        reason: "9p symlink target is not UTF-8",
                    }
                })?;
                codec::encode_rreadlink(tag, target)?
            }
        }
        TMessage::Xattrwalk { newfid, .. } => {
            virtual_fids.insert(*newfid, binding);
            codec::encode_rxattrwalk(tag, 0)?
        }
        _ => {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p object result does not support this request shape",
            });
        }
    };
    Ok(reply)
}
