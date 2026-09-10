//! Loopback-only browser for bounded ability operator views.
//!
//! The server renders every page from the checked [`InspectionView`] held in
//! memory. Projection changes and continuation expansion are ordinary GET
//! navigation, so the interface remains usable without JavaScript and every
//! clicked continuation executes the shared [`GraphQuery`] implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use aos_ability_inspect::{
    Direction, ExpansionHint, GenerationAxis, GenerationConvergence, GraphQuery,
    INSPECTION_QUERY_MAX_NODES, InspectionEdge, InspectionNode, InspectionProjection,
    InspectionRelation, InspectionView, NodeKey, OperatorFocus, OperatorGroup, OperatorGroupKey,
    OperatorNodeState, OperatorNodeStatus, OperatorObservation, OperatorObservationProvenance,
    OperatorQuery, OperatorView, ProjectionKind, ViewAnchor,
};
use aos_ability_model::PlanId;
use aos_contract::Sha256Digest;
use aos_core::output::Printer;
use axum::Router;
use axum::extract::{RawQuery, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

const CSS: &str = include_str!("browser.css");
const MAX_OPEN_BOUNDARIES: usize = INSPECTION_QUERY_MAX_NODES;
const BOUNDARY_DOMAIN: &str = "aos.ability.operator-browser-boundary/v1";

const PROJECTIONS: [ProjectionKind; 4] = [
    ProjectionKind::Composition,
    ProjectionKind::BindingAuthority,
    ProjectionKind::Activation,
    ProjectionKind::Retention,
];

/// Serves one immutable checked operator source on a loopback socket.
///
/// # Errors
///
/// Returns an error when the requested address is not loopback, the listener
/// cannot bind, the initial operator view is invalid, or the HTTP server exits
/// with an error.
pub(super) async fn serve(
    view: InspectionView,
    query: OperatorQuery,
    observation: Option<OperatorObservation>,
    listen: SocketAddr,
    printer: &Printer,
) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("the ability operator browser may listen only on a loopback address");
    }

    let browser = OperatorBrowser::new(view, query, observation)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding ability operator browser to {listen}"))?;
    let address = listener
        .local_addr()
        .context("reading ability operator browser address")?;
    printer.raw(&format!("http://{address}/"));

    axum::serve(listener, browser.router(address))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving ability operator browser")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Clone)]
struct OperatorBrowser {
    view: InspectionView,
    query: OperatorQuery,
    observation: Option<OperatorObservation>,
}

#[derive(Clone)]
struct BoundAuthority(String);

impl OperatorBrowser {
    fn new(
        view: InspectionView,
        query: OperatorQuery,
        observation: Option<OperatorObservation>,
    ) -> Result<Self> {
        OperatorView::from_view(&view, &query, observation.as_ref())
            .context("building initial operator browser view")?;
        Ok(Self {
            view,
            query,
            observation,
        })
    }

    fn router(self, authority: SocketAddr) -> Router {
        Router::new()
            .route("/", get(render_handler))
            .route("/operator.css", get(css_handler))
            .layer(axum::middleware::from_fn_with_state(
                BoundAuthority(authority.to_string()),
                enforce_bound_authority,
            ))
            .with_state(Arc::new(self))
    }

    fn render(&self, location: &BrowserLocation) -> Result<String> {
        let document = self.document(location)?;
        render_document(&document)
    }

    fn document(&self, location: &BrowserLocation) -> Result<BrowserDocument> {
        let projection = self
            .view
            .project(location.projection)
            .context("building selected operator projection")?;
        let initial_query = OperatorQuery::new(
            self.query.focus().clone(),
            location.projection,
            self.query.graph().max_depth(),
            self.query.graph().max_nodes(),
        )
        .with_direction(self.query.graph().direction());
        let initial =
            OperatorView::from_view(&self.view, &initial_query, self.observation.as_ref())
                .context("building selected operator view")?;
        let mut nodes = initial
            .slice()
            .nodes()
            .iter()
            .cloned()
            .map(|node| (node.key(), node))
            .collect::<BTreeMap<_, _>>();
        let mut edges = initial
            .slice()
            .edges()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut opened = Vec::new();
        let mut opened_tokens = BTreeSet::new();

        loop {
            let visible = nodes.keys().cloned().collect::<BTreeSet<_>>();
            let hints = expansion_hints(&projection, &visible, self.query.graph().max_nodes())?;
            let next = location.open.iter().find_map(|requested| {
                if opened_tokens.contains(requested) {
                    return None;
                }
                hints.iter().find(|hint| hint.token == *requested).cloned()
            });
            let Some(expansion) = next else {
                break;
            };

            let hint = hints
                .iter()
                .find(|hint| hint.token == expansion.token)
                .ok_or_else(|| anyhow::anyhow!("operator continuation disappeared"))?;
            let continuation = projection
                .query(&hint.query)
                .context("executing operator continuation query")?;
            let previous_node_count = nodes.len();
            nodes.extend(
                continuation
                    .nodes()
                    .iter()
                    .cloned()
                    .map(|node| (node.key(), node)),
            );
            if nodes.len() == previous_node_count {
                bail!("operator continuation did not advance the visible graph");
            }
            edges.extend(continuation.edges().iter().cloned());
            opened_tokens.insert(expansion.token.clone());
            opened.push(expansion);
        }

        if location
            .open
            .iter()
            .any(|requested| !opened_tokens.contains(requested))
        {
            bail!("an open continuation boundary is not reachable in this projection");
        }

        let visible = nodes.keys().cloned().collect::<BTreeSet<_>>();
        let expansion = expansion_hints(&projection, &visible, self.query.graph().max_nodes())?;
        let nodes = nodes.into_values().collect::<Vec<_>>();
        let edges = edges.into_iter().collect::<Vec<_>>();
        let metadata = projection
            .operator_slice_metadata(&nodes, &edges, self.observation.as_ref())
            .context("building operator browser slice metadata")?;
        let statuses = metadata
            .statuses()
            .iter()
            .cloned()
            .map(|status| (status.node.clone(), status))
            .collect();
        let groups = metadata.groups().to_vec();

        Ok(BrowserDocument {
            projection: location.projection,
            anchor: initial.anchor().clone(),
            plan: initial.slice().plan(),
            binding_plan: initial.slice().binding_plan(),
            focus: initial.focus().clone(),
            observation: initial.observation(),
            generations: initial.generations().to_vec(),
            nodes,
            edges,
            statuses,
            groups,
            opened,
            expansion,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BrowserLocation {
    projection: ProjectionKind,
    open: Vec<String>,
}

impl BrowserLocation {
    fn parse(raw: Option<&str>, default_projection: ProjectionKind) -> Result<Self> {
        let mut projection = None;
        let mut open = None;

        if let Some(raw) = raw.filter(|raw| !raw.is_empty()) {
            for pair in raw.split('&') {
                let (name, value) = pair
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("browser query fields require values"))?;
                match name {
                    "projection" if projection.is_none() => {
                        projection = Some(parse_projection(value)?);
                    }
                    "open" if open.is_none() => {
                        open = Some(parse_open_boundaries(value)?);
                    }
                    "projection" | "open" => bail!("browser query fields may not repeat"),
                    _ => bail!("unsupported ability operator browser query field"),
                }
            }
        }

        Ok(Self {
            projection: projection.unwrap_or(default_projection),
            open: open.unwrap_or_default(),
        })
    }

    fn url(&self) -> String {
        let mut url = format!("/?projection={}", projection_name(self.projection));
        if !self.open.is_empty() {
            url.push_str("&open=");
            url.push_str(&self.open.join(","));
        }
        url
    }

    fn with_projection(&self, projection: ProjectionKind) -> Self {
        Self {
            projection,
            open: Vec::new(),
        }
    }

    fn with_expansion(&self, token: String) -> Self {
        let mut open = self.open.clone();
        open.push(token);
        Self {
            projection: self.projection,
            open,
        }
    }

    fn collapsed_at(&self, opened_index: usize) -> Self {
        Self {
            projection: self.projection,
            open: self.open.iter().take(opened_index).cloned().collect(),
        }
    }
}

#[derive(Clone)]
struct BrowserExpansion {
    token: String,
    node: NodeKey,
    hidden_incoming: usize,
    hidden_outgoing: usize,
    query: GraphQuery,
}

struct BrowserDocument {
    projection: ProjectionKind,
    anchor: ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    focus: OperatorFocus,
    observation: Option<aos_ability_inspect::OperatorObservationSummary>,
    generations: Vec<aos_ability_inspect::GenerationObservation>,
    nodes: Vec<InspectionNode>,
    edges: Vec<InspectionEdge>,
    statuses: BTreeMap<NodeKey, OperatorNodeStatus>,
    groups: Vec<OperatorGroup>,
    opened: Vec<BrowserExpansion>,
    expansion: Vec<BrowserExpansion>,
}

async fn render_handler(
    State(browser): State<Arc<OperatorBrowser>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let response = BrowserLocation::parse(raw_query.as_deref(), browser.query.projection())
        .and_then(|location| browser.render(&location))
        .map_or_else(
            |error| {
                (
                    StatusCode::BAD_REQUEST,
                    Html(format!(
                        "<!doctype html><meta charset=\"utf-8\"><title>Invalid operator navigation</title><main><h1>Invalid operator navigation</h1><p>{}</p><p><a href=\"/\">Return to the operator view</a></p></main>",
                        escape_html(&error.to_string())
                    )),
                )
                    .into_response()
            },
            |page| Html(page).into_response(),
        );
    secure_response(response)
}

async fn enforce_bound_authority(
    State(authority): State<BoundAuthority>,
    request: Request,
    next: Next,
) -> Response {
    let mut hosts = request.headers().get_all(header::HOST).iter();
    let valid = match (hosts.next(), hosts.next()) {
        (Some(host), None) => host.to_str().is_ok_and(|host| host == authority.0),
        _ => false,
    };
    if !valid {
        return secure_response(
            (
                StatusCode::MISDIRECTED_REQUEST,
                "invalid operator browser authority",
            )
                .into_response(),
        );
    }
    secure_response(next.run(request).await)
}

async fn css_handler() -> Response {
    let mut response = CSS.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    secure_response(response)
}

fn secure_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn parse_projection(value: &str) -> Result<ProjectionKind> {
    match value {
        "composition" => Ok(ProjectionKind::Composition),
        "binding-authority" => Ok(ProjectionKind::BindingAuthority),
        "activation" => Ok(ProjectionKind::Activation),
        "retention" => Ok(ProjectionKind::Retention),
        _ => bail!("unknown ability operator projection"),
    }
}

fn parse_open_boundaries(value: &str) -> Result<Vec<String>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = value.split(',').map(str::to_string).collect::<Vec<_>>();
    if tokens.len() > MAX_OPEN_BOUNDARIES {
        bail!("too many open ability operator boundaries");
    }
    if tokens
        .iter()
        .any(|token| token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        bail!("ability operator boundary identities must be 64 lowercase hexadecimal digits");
    }
    if tokens
        .iter()
        .any(|token| token.bytes().any(|byte| byte.is_ascii_uppercase()))
    {
        bail!("ability operator boundary identities must use lowercase hexadecimal digits");
    }
    if tokens.iter().collect::<BTreeSet<_>>().len() != tokens.len() {
        bail!("ability operator boundary identities may not repeat");
    }
    Ok(tokens)
}

fn expansion_hints(
    projection: &InspectionProjection,
    visible: &BTreeSet<NodeKey>,
    query_node_limit: usize,
) -> Result<Vec<BrowserExpansion>> {
    projection
        .continuation_hints(visible, query_node_limit)?
        .into_iter()
        .map(|hint: ExpansionHint| {
            let token = Sha256Digest::of_canonical(BOUNDARY_DOMAIN, &hint.query)?.hex();
            Ok(BrowserExpansion {
                query: hint.query,
                token,
                node: hint.node,
                hidden_incoming: hint.hidden_incoming,
                hidden_outgoing: hint.hidden_outgoing,
            })
        })
        .collect()
}

fn render_document(document: &BrowserDocument) -> Result<String> {
    let location = BrowserLocation {
        projection: document.projection,
        open: document
            .opened
            .iter()
            .map(|boundary| boundary.token.clone())
            .collect(),
    };
    let mut html = String::with_capacity(32 * 1024);
    html.push_str(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Ability operator · AOS</title><link rel=\"stylesheet\" href=\"/operator.css\">\
         </head><body><a class=\"skip-link\" href=\"#graph\">Skip to graph</a><header class=\"masthead\">\
         <p class=\"eyebrow\">AOS ability operator</p><h1>Desired plan and observed state</h1>\
         <p class=\"lede\">Choose a projection, then expand a boundary to inspect more relationships.</p></header><main>",
    );

    render_provenance(&mut html, document)?;
    render_projection_navigation(&mut html, &location);
    render_generations(&mut html, document)?;
    render_groups(&mut html, document)?;
    render_graph(&mut html, document, &location)?;

    html.push_str(
        "</main><footer><span>Local read-only operator browser</span><span>Desired and observed state stay separate</span></footer></body></html>",
    );
    Ok(html)
}

fn render_provenance(html: &mut String, document: &BrowserDocument) -> Result<()> {
    let (anchor_class, anchor_title, anchor_detail, anchor_digest) = match &document.anchor {
        ViewAnchor::LocallyChecked => (
            "local",
            "Locally checked desired plan",
            "The in-memory plan passed semantic validation.",
            None,
        ),
        ViewAnchor::UnanchoredBundle { digest } => (
            "unanchored",
            "Unanchored desired bundle",
            "The bundle passed semantic validation without an independently supplied digest.",
            Some(*digest),
        ),
        ViewAnchor::ExternallyAnchoredBundle { digest } => (
            "anchored",
            "Externally anchored desired bundle",
            "The exact bundle matched an independently supplied digest.",
            Some(*digest),
        ),
    };
    let focus = json_text(&document.focus)?;
    write!(
        html,
        "<section class=\"provenance-grid\" aria-label=\"View provenance\"><article class=\"provenance {anchor_class}\"><p class=\"label\">Desired source</p><h2>{anchor_title}</h2><p>{anchor_detail}</p><p class=\"limit\">This anchor does not assert that the plan is the current deployment target or authoritative policy.</p><dl><dt>Focus</dt><dd><code>{}</code></dd><dt>Effect plan</dt><dd><code>{}</code></dd><dt>Binding plan</dt><dd><code>{}</code></dd>",
        escape_html(&focus),
        document.plan.0,
        document.binding_plan.0,
    )?;
    if let Some(digest) = anchor_digest {
        write!(html, "<dt>Bundle digest</dt><dd><code>{digest}</code></dd>")?;
    }
    html.push_str("</dl></article>");
    match document.observation {
        Some(observation) => {
            let OperatorObservationProvenance::CallerAssertedEvidence { evidence } =
                observation.provenance;
            write!(
                html,
                "<article class=\"provenance observed\"><p class=\"label\">Observed source</p><h2>Caller-asserted evidence</h2><p>The overlay is separate from desired state. This view does not authenticate its source or establish freshness.</p><dl><dt>Evidence</dt><dd><code>{}</code></dd><dt>Captured</dt><dd>{} ms since Unix epoch</dd></dl></article>",
                evidence,
                observation.captured_unix_millis,
            )?;
        }
        None => html.push_str(
            "<article class=\"provenance absent\"><p class=\"label\">Observed source</p><h2>No observation supplied</h2><p>Observed state is shown as unavailable and is never inferred from the desired plan.</p></article>",
        ),
    }
    html.push_str("</section>");
    Ok(())
}

fn render_projection_navigation(html: &mut String, location: &BrowserLocation) {
    html.push_str(
        "<nav class=\"projections\" aria-label=\"Graph projection\"><span>Projection</span>",
    );
    for projection in PROJECTIONS {
        let selected = projection == location.projection;
        let next = location.with_projection(projection).url();
        let current = if selected {
            " aria-current=\"page\""
        } else {
            ""
        };
        let class = if selected {
            "projection selected"
        } else {
            "projection"
        };
        let _ = write!(
            html,
            "<a class=\"{class}\" href=\"{next}\"{current}>{}</a>",
            projection_title(projection),
        );
    }
    html.push_str("</nav>");
}

fn render_generations(html: &mut String, document: &BrowserDocument) -> Result<()> {
    html.push_str("<section class=\"section\"><div class=\"section-heading\"><p class=\"eyebrow\">Convergence</p><h2>Independent generations</h2></div>");
    if document.generations.is_empty() {
        html.push_str("<p class=\"empty\">No caller-supplied generation observations.</p>");
    } else {
        html.push_str("<div class=\"generation-grid\">");
        for generation in &document.generations {
            let desired = json_text(&generation.desired())?;
            let observed = generation
                .observed()
                .map(|revision| json_text(&revision))
                .transpose()?
                .unwrap_or_else(|| "unobserved".to_string());
            let environment = json_text(generation.environment())?;
            write!(
                html,
                "<article class=\"generation\"><h3>{}</h3><p class=\"environment\"><code>{}</code></p><dl><dt>Desired</dt><dd><code>{}</code></dd><dt>Observed</dt><dd><code>{}</code></dd><dt>Convergence</dt><dd><span class=\"state {}\">{}</span></dd></dl></article>",
                generation_axis_title(generation.axis()),
                escape_html(&environment),
                escape_html(&desired),
                escape_html(&observed),
                convergence_class(generation.convergence()),
                convergence_title(generation.convergence()),
            )?;
        }
        html.push_str("</div>");
    }
    html.push_str("</section>");
    Ok(())
}

fn render_groups(html: &mut String, document: &BrowserDocument) -> Result<()> {
    html.push_str("<section class=\"section\"><div class=\"section-heading\"><p class=\"eyebrow\">Contexts</p><h2>Visible graph groups</h2></div>");
    if document.groups.is_empty() {
        html.push_str("<p class=\"empty\">The visible slice has no environment, provider, or transaction grouping.</p>");
    } else {
        html.push_str("<div class=\"group-grid\">");
        for group in &document.groups {
            let key = json_text(&group.key)?;
            write!(
                html,
                "<details class=\"group\"><summary><span>{}</span><code>{}</code><b>{}</b></summary><ul>",
                group_kind(&group.key),
                escape_html(&key),
                group.members.len(),
            )?;
            for member in &group.members {
                let identity = json_text(member)?;
                write!(html, "<li><code>{}</code></li>", escape_html(&identity))?;
            }
            html.push_str("</ul></details>");
        }
        html.push_str("</div>");
    }
    html.push_str("</section>");
    Ok(())
}

fn render_graph(
    html: &mut String,
    document: &BrowserDocument,
    location: &BrowserLocation,
) -> Result<()> {
    write!(
        html,
        "<section class=\"section\" id=\"graph\"><div class=\"section-heading graph-heading\"><div><p class=\"eyebrow\">Typed graph</p><h2>{} projection</h2></div><p>{} nodes · {} edges</p></div>",
        projection_title(document.projection),
        document.nodes.len(),
        document.edges.len(),
    )?;
    render_continuations(html, document, location)?;

    html.push_str("<div class=\"node-grid\">");
    for node in &document.nodes {
        let key = node.key();
        let identity = json_text(&key)?;
        let details = json_text(node)?;
        let status = document.statuses.get(&key);
        let desired = status.map_or("unverified", |status| state_name(status.plan_state));
        let observed = status
            .and_then(|status| status.observed_state)
            .map(state_name)
            .unwrap_or("no observation");
        write!(
            html,
            "<article class=\"node\"><div class=\"node-title\"><span class=\"node-kind\">{}</span><code>{}</code></div><dl class=\"state-pair\"><div><dt>Desired state</dt><dd><span class=\"state state-{desired}\">{}</span></dd></div><div><dt>Observed state</dt><dd><span class=\"state state-{}\">{}</span></dd></div></dl><details><summary>Desired node details</summary><pre>{}</pre></details></article>",
            node_kind(&key),
            escape_html(&identity),
            state_title(desired),
            observed.replace(' ', "-"),
            state_title(observed),
            escape_html(&details),
        )?;
    }
    html.push_str("</div><div class=\"edges\"><h3>Typed relationships</h3>");
    if document.edges.is_empty() {
        html.push_str(
            "<p class=\"empty\">No relationship lies wholly inside this bounded slice.</p>",
        );
    } else {
        html.push_str("<ol>");
        for edge in &document.edges {
            let from = json_text(&edge.from)?;
            let to = json_text(&edge.to)?;
            write!(
                html,
                "<li><code>{}</code><strong>{}</strong><code>{}</code></li>",
                escape_html(&from),
                relation_name(edge.relation)?,
                escape_html(&to),
            )?;
        }
        html.push_str("</ol>");
    }
    html.push_str("</div></section>");
    Ok(())
}

fn render_continuations(
    html: &mut String,
    document: &BrowserDocument,
    location: &BrowserLocation,
) -> Result<()> {
    html.push_str("<div class=\"continuations\"><div><h3>Open continuation boundaries</h3>");
    if document.opened.is_empty() {
        html.push_str("<p class=\"empty\">No continuation is open.</p>");
    } else {
        html.push_str("<ol>");
        for (index, boundary) in document.opened.iter().enumerate() {
            let identity = json_text(&boundary.node)?;
            let direction = direction_name(boundary.query.direction());
            let collapse = location.collapsed_at(index).url();
            write!(
                html,
                "<li><code>{}</code><span>{direction} page</span><a class=\"boundary-action\" href=\"{}\">Collapse here</a></li>",
                escape_html(&identity),
                collapse,
            )?;
        }
        html.push_str("</ol>");
    }
    html.push_str("</div><div><h3>Available continuations</h3>");
    if document.expansion.is_empty() {
        html.push_str(
            "<p class=\"empty\">Every adjacent relationship in this projection is visible.</p>",
        );
    } else {
        html.push_str("<ol>");
        for boundary in &document.expansion {
            let identity = json_text(&boundary.node)?;
            let direction = direction_name(boundary.query.direction());
            let expand = location.with_expansion(boundary.token.clone()).url();
            write!(
                html,
                "<li><code>{}</code><span>{direction}: {} incoming · {} outgoing hidden</span><a class=\"boundary-action\" href=\"{}\">Expand boundary</a></li>",
                escape_html(&identity),
                boundary.hidden_incoming,
                boundary.hidden_outgoing,
                expand,
            )?;
        }
        html.push_str("</ol>");
    }
    html.push_str("</div></div>");
    Ok(())
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Incoming => "incoming",
        Direction::Outgoing => "outgoing",
        Direction::Both => "both directions",
    }
}

fn projection_name(projection: ProjectionKind) -> &'static str {
    match projection {
        ProjectionKind::Composition => "composition",
        ProjectionKind::BindingAuthority => "binding-authority",
        ProjectionKind::Activation => "activation",
        ProjectionKind::Retention => "retention",
    }
}

fn projection_title(projection: ProjectionKind) -> &'static str {
    match projection {
        ProjectionKind::Composition => "Composition",
        ProjectionKind::BindingAuthority => "Binding & authority",
        ProjectionKind::Activation => "Activation",
        ProjectionKind::Retention => "Retention",
    }
}

fn node_kind(node: &NodeKey) -> &'static str {
    match node {
        NodeKey::Interface(_) => "Interface",
        NodeKey::Package(_) => "Package",
        NodeKey::Request(_) => "Request",
        NodeKey::Binding(_) => "Binding",
        NodeKey::Provider(_) => "Provider",
        NodeKey::Aggregate(_) => "Aggregate",
        NodeKey::Operation(_) => "Operation",
        NodeKey::Decision(_) => "Decision",
        NodeKey::Merge(_) => "Merge",
        NodeKey::Artifact(_) => "Artifact",
        NodeKey::Resource(_) => "Resource",
        NodeKey::Obligation(_) => "Obligation",
    }
}

fn state_name(state: OperatorNodeState) -> &'static str {
    match state {
        OperatorNodeState::Declared => "declared",
        OperatorNodeState::Planned => "planned",
        OperatorNodeState::Available => "available",
        OperatorNodeState::Failed => "failed",
        OperatorNodeState::Stale => "stale",
        OperatorNodeState::Unverified => "unverified",
    }
}

fn state_title(state: &str) -> String {
    let mut characters = state.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
        None => String::new(),
    }
}

fn relation_name(relation: InspectionRelation) -> Result<String> {
    let encoded = serde_json::to_string(&relation).context("encoding graph relation")?;
    Ok(encoded.trim_matches('"').to_string())
}

fn group_kind(group: &OperatorGroupKey) -> &'static str {
    match group {
        OperatorGroupKey::Environment(_) => "Environment",
        OperatorGroupKey::Provider(_) => "Provider",
        OperatorGroupKey::Transaction(_) => "Transaction",
    }
}

fn generation_axis_title(axis: &GenerationAxis) -> String {
    match axis {
        GenerationAxis::PackageProfile => "Package profile".to_string(),
        GenerationAxis::Configuration => "Configuration".to_string(),
        GenerationAxis::Image => "Image".to_string(),
        GenerationAxis::UserProfile { user } => format!("User profile · {}", user.as_str()),
    }
}

fn convergence_title(convergence: GenerationConvergence) -> &'static str {
    match convergence {
        GenerationConvergence::Unobserved => "Unobserved",
        GenerationConvergence::Converged => "Converged",
        GenerationConvergence::Diverged => "Diverged",
    }
}

fn convergence_class(convergence: GenerationConvergence) -> &'static str {
    match convergence {
        GenerationConvergence::Unobserved => "state-unverified",
        GenerationConvergence::Converged => "state-available",
        GenerationConvergence::Diverged => "state-failed",
    }
}

fn json_text<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("encoding operator browser identity")
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use aos_ability_inspect::{
        GenerationObservation, InspectionBundle, NodeObservation, ObservedNodeState,
        TransactionObservation,
    };
    use aos_ability_model::{LocalKey, RevisionId, TransactionId};
    use aos_ability_validate::test_support::checked_effect_plan;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;

    #[test]
    fn successful_fixture_switches_projection_and_expands_then_collapses_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let provider = view
            .nodes()
            .iter()
            .find_map(|node| match node {
                InspectionNode::Provider { id, .. } => Some(id.clone()),
                _ => None,
            })
            .ok_or("provider fixture is missing")?;
        let query = OperatorQuery::new(
            OperatorFocus::Instance { id: provider },
            ProjectionKind::Composition,
            0,
            1,
        );
        let browser = OperatorBrowser::new(view, query, None)?;
        let initial = BrowserLocation::parse(None, ProjectionKind::Composition)?;
        let initial_document = browser.document(&initial)?;
        let boundary = initial_document
            .expansion
            .first()
            .ok_or("continuation fixture is missing")?;

        let expanded_location = initial.with_expansion(boundary.token.clone());
        let expanded = browser.document(&expanded_location)?;
        assert!(expanded.nodes.len() > initial_document.nodes.len());
        assert_eq!(expanded.statuses.len(), expanded.nodes.len());
        assert!(
            expanded
                .nodes
                .iter()
                .all(|node| { expanded.statuses.contains_key(&node.key()) })
        );
        let initial_nodes = initial_document
            .nodes
            .iter()
            .map(InspectionNode::key)
            .collect::<BTreeSet<_>>();
        assert!(expanded.groups.iter().any(|group| {
            group
                .members
                .iter()
                .any(|member| !initial_nodes.contains(member))
        }));
        assert_eq!(expanded.opened.len(), 1);
        let expanded_html = browser.render(&expanded_location)?;
        assert!(expanded_html.contains("Collapse here"));
        assert!(expanded_html.contains("Desired state"));
        assert!(expanded_html.contains("Observed state"));

        let collapsed = expanded_location.collapsed_at(0);
        assert_eq!(browser.document(&collapsed)?.nodes, initial_document.nodes);
        let retention =
            BrowserLocation::parse(Some("projection=retention"), ProjectionKind::Composition)?;
        assert_eq!(
            browser.document(&retention)?.projection,
            ProjectionKind::Retention
        );
        assert!(browser.render(&retention)?.contains("Retention projection"));
        Ok(())
    }

    #[tokio::test]
    async fn router_serves_no_script_navigation_with_security_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        let bundle = InspectionBundle::from_checked(&checked_effect_plan())?;
        let digest = bundle.digest()?;
        let checked = bundle.check(Some(digest))?;
        let view = InspectionView::from_bundle(&checked)?;
        let provider = view
            .nodes()
            .iter()
            .find_map(|node| match node {
                InspectionNode::Provider { id, .. } => Some(id.clone()),
                _ => None,
            })
            .ok_or("provider fixture is missing")?;
        let query = OperatorQuery::new(
            OperatorFocus::Instance { id: provider },
            ProjectionKind::Composition,
            0,
            1,
        );
        let authority = SocketAddr::from(([127, 0, 0, 1], 4317));
        let response = OperatorBrowser::new(view, query, None)?
            .router(authority)
            .oneshot(
                Request::builder()
                    .uri("/?projection=composition")
                    .header(header::HOST, authority.to_string())
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store, max-age=0"
        );
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()?
                .contains("default-src 'none'")
        );
        let body = to_bytes(
            response.into_body(),
            aos_ability_inspect::OPERATOR_VIEW_MAX_BYTES,
        )
        .await?;
        let html = std::str::from_utf8(&body)?;
        assert!(html.contains("Externally anchored desired bundle"));
        assert!(html.contains(&digest.to_string()));
        assert!(html.contains("Projection"));
        assert!(html.contains("Expand boundary"));
        assert!(!html.contains("<script"));
        Ok(())
    }

    #[tokio::test]
    async fn host_authority_requires_the_exact_ipv4_or_ipv6_bound_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let ipv4 = SocketAddr::from(([127, 0, 0, 1], 4317));
        let ipv6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 4317));

        for authority in [ipv4, ipv6] {
            let response = authority_router(authority)
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, authority.to_string())
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
        }

        let missing = authority_router(ipv4)
            .oneshot(Request::builder().uri("/").body(Body::empty())?)
            .await?;
        assert_eq!(missing.status(), StatusCode::MISDIRECTED_REQUEST);

        let wrong_port = authority_router(ipv4)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "127.0.0.1:4318")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_port.status(), StatusCode::MISDIRECTED_REQUEST);

        let repeated = authority_router(ipv4)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, ipv4.to_string())
                    .header(header::HOST, ipv4.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(repeated.status(), StatusCode::MISDIRECTED_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn host_authority_uses_the_kernel_assigned_ephemeral_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let authority = listener.local_addr()?;
        assert_ne!(authority.port(), 0);

        let accepted = authority_router(authority)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, authority.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(accepted.status(), StatusCode::OK);

        let requested = authority_router(authority)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "127.0.0.1:0")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(requested.status(), StatusCode::MISDIRECTED_REQUEST);
        Ok(())
    }

    fn authority_router(authority: SocketAddr) -> Router {
        Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                BoundAuthority(authority.to_string()),
                enforce_bound_authority,
            ))
    }

    #[test]
    fn high_degree_boundary_advances_through_distinct_pages_and_terminates()
    -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let provider = view
            .nodes()
            .iter()
            .find_map(|node| match node {
                InspectionNode::Provider { id, .. } => Some(id.clone()),
                _ => None,
            })
            .ok_or("provider fixture is missing")?;
        let query = OperatorQuery::new(
            OperatorFocus::Instance { id: provider },
            ProjectionKind::Composition,
            0,
            1,
        );
        let browser = OperatorBrowser::new(view, query, None)?;
        let initial = BrowserLocation::parse(None, ProjectionKind::Composition)?;
        let initial_document = browser.document(&initial)?;
        let provider_page = initial_document
            .expansion
            .iter()
            .find(|boundary| boundary.query.direction() == Direction::Outgoing)
            .ok_or("provider fixture has no outgoing continuation")?;

        let request_location = initial.with_expansion(provider_page.token.clone());
        let request_document = browser.document(&request_location)?;
        let first_page = request_document
            .expansion
            .iter()
            .find(|boundary| {
                boundary.query.direction() == Direction::Outgoing && boundary.hidden_outgoing >= 2
            })
            .ok_or("fixture has no high-degree outgoing boundary")?;
        let target_node = first_page.node.clone();
        let target_direction = first_page.query.direction();
        let mut location = request_location;
        let mut document = request_document;
        let mut page_tokens = BTreeSet::new();

        loop {
            let Some(page) = document
                .expansion
                .iter()
                .find(|boundary| {
                    boundary.node == target_node && boundary.query.direction() == target_direction
                })
                .cloned()
            else {
                break;
            };
            if page_tokens.is_empty() {
                assert!(page.query.after().is_none());
            } else {
                assert!(page.query.after().is_some());
            }
            assert!(page_tokens.insert(page.token.clone()));

            let previous_node_count = document.nodes.len();
            location = location.with_expansion(page.token);
            document = browser.document(&location)?;
            assert!(document.nodes.len() > previous_node_count);
            assert!(page_tokens.len() <= INSPECTION_QUERY_MAX_NODES);
        }

        assert!(page_tokens.len() >= 2);
        Ok(())
    }

    #[test]
    fn failed_fixture_keeps_desired_and_observed_text_visibly_separate()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let view = InspectionView::from_checked(&plan)?;
        let request = view
            .nodes()
            .iter()
            .find_map(|node| match node {
                InspectionNode::Request { id, .. } => Some(id.clone()),
                _ => None,
            })
            .ok_or("request fixture is missing")?;
        let request_node = NodeKey::Request(request.clone());
        let observation = OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("caller supplied failed fixture"),
            1_725_900_000_000,
            vec![GenerationObservation::new(
                request.consumer.environment.clone(),
                GenerationAxis::Configuration,
                RevisionId(Sha256Digest::of_bytes("desired configuration")),
                Some(RevisionId(Sha256Digest::of_bytes("observed configuration"))),
            )],
            vec![NodeObservation {
                node: request_node.clone(),
                state: ObservedNodeState::Failed,
            }],
            vec![TransactionObservation {
                transaction: TransactionId(LocalKey::new("failed-activation")?),
                members: vec![request_node],
            }],
        )?;
        let query = OperatorQuery::new(
            OperatorFocus::FailingRequest { id: request },
            ProjectionKind::Composition,
            1,
            16,
        );
        let browser = OperatorBrowser::new(view, query, Some(observation))?;
        let location = BrowserLocation::parse(None, ProjectionKind::Composition)?;
        let html = browser.render(&location)?;

        assert!(html.contains("Caller-asserted evidence"));
        assert!(html.contains("Desired state"));
        assert!(html.contains(">Declared<"));
        assert!(html.contains("Observed state"));
        assert!(html.contains(">Failed<"));
        assert!(html.contains("Diverged"));
        assert!(html.contains("Transaction"));
        assert!(html.contains("does not authenticate its source or establish freshness"));
        Ok(())
    }

    #[test]
    fn browser_navigation_rejects_unknown_or_repeated_state() {
        assert!(
            BrowserLocation::parse(Some("projection=unknown"), ProjectionKind::Composition)
                .is_err()
        );
        assert!(BrowserLocation::parse(Some("other=value"), ProjectionKind::Composition).is_err());
        assert!(
            BrowserLocation::parse(
                Some("projection=retention&projection=activation"),
                ProjectionKind::Composition
            )
            .is_err()
        );
        assert!(BrowserLocation::parse(Some("open=ABC"), ProjectionKind::Composition).is_err());
    }

    #[test]
    fn html_escaping_covers_identity_delimiters() {
        assert_eq!(escape_html("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
    }

    #[test]
    fn projection_names_are_stable() {
        for projection in PROJECTIONS {
            assert!(matches!(
                parse_projection(projection_name(projection)),
                Ok(parsed) if parsed == projection
            ));
        }
    }
}
