//! Interactive terminal browser for the documentation index.
//!
//! Built on ratatui + crossterm, the TUI presents the [`DocIndex`] across
//! four tabs, switched with the `1`-`4` keys:
//!
//! 1. **Language** -- chapter/topic tree of the Nix language reference
//! 2. **Functions** -- module tree, function list, and detail panes
//! 3. **Options** -- namespace tree, option list, and detail panes
//! 4. **Packages** -- package tree and detail pane
//!
//! Navigation is vim-flavored (`j`/`k` move, `h`/`l`/Tab switch panes,
//! Enter expands tree nodes, `d`/`u` scroll the detail pane) and `/` opens
//! a fuzzy-search overlay backed by [`fuzzy_search`] that can jump to any
//! entry. `q` or Ctrl+C quits.
//!
//! Internally, every tab's left-hand navigation is a generic `TreeState`
//! built from the dotted entry paths; all mutable UI state lives in the
//! `App` struct, drawn fresh each frame by `draw`.

use std::io;

use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Direction, Layout, Rect},
    prelude::CrosstermBackend,
    style::{Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};

use crate::model::{DocCategory, DocEntry, DocIndex};
use crate::search::fuzzy_search;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Runs the interactive documentation browser until the user quits.
///
/// Takes ownership of the index and drives the blocking TUI event loop on a
/// dedicated thread (via `tokio::task::spawn_blocking`) so the async runtime
/// is not stalled. The terminal is switched into raw mode and the alternate
/// screen for the duration of the session and restored on exit.
///
/// # Errors
///
/// Returns an error if the terminal cannot be put into raw mode or the
/// alternate screen, if reading input events or drawing a frame fails, or
/// if the TUI task panics.
pub async fn run(index: DocIndex) -> anyhow::Result<()> {
    // Run the blocking TUI event loop off the async runtime.
    tokio::task::spawn_blocking(move || run_blocking(&index))
        .await
        .map_err(|e| anyhow::anyhow!("TUI task panicked: {e}"))?
}

/// Sets up the terminal, runs the event loop, and restores the terminal.
///
/// Raw mode and the alternate screen are torn down even when the event loop
/// returns an error, so the user's shell is left usable.
fn run_blocking(index: &DocIndex) -> anyhow::Result<()> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_event_loop(&mut terminal, index);

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    result
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// The four top-level tabs, switched with the `1`-`4` keys.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Language,
    Functions,
    Options,
    Packages,
}

impl Tab {
    /// All tabs in display order (matching the `1`-`4` key bindings).
    const ALL: [Tab; 4] = [Tab::Language, Tab::Functions, Tab::Options, Tab::Packages];

    /// Returns this tab's position in the tab bar.
    fn index(self) -> usize {
        match self {
            Tab::Language => 0,
            Tab::Functions => 1,
            Tab::Options => 2,
            Tab::Packages => 3,
        }
    }

    /// Returns the human-readable tab title.
    fn title(self) -> &'static str {
        match self {
            Tab::Language => "Language",
            Tab::Functions => "Functions",
            Tab::Options => "Options",
            Tab::Packages => "Packages",
        }
    }
}

/// A node in a navigation tree, stored in a flat arena indexed by `usize`.
struct TreeNode {
    /// Display text (one path component, chapter, or topic name).
    label: String,
    /// Nesting depth, used for indentation (0 = root).
    depth: usize,
    /// Whether the node's children are currently shown.
    expanded: bool,
    /// Arena indices of child nodes, in display order.
    children: Vec<usize>,
    /// Index into the entries vec when this node is a documented leaf.
    entry_idx: Option<usize>,
    /// Arena index of the parent node (`None` for roots).
    parent: Option<usize>,
}

/// An expandable/collapsible tree plus its list-widget selection state.
///
/// `visible` is the flattened pre-order list of node indices that are
/// currently shown given each node's `expanded` flag; the ratatui
/// [`ListState`] selection indexes into `visible`.
struct TreeState {
    nodes: Vec<TreeNode>,
    visible: Vec<usize>,
    list_state: ListState,
}

impl TreeState {
    /// Creates a tree from arena nodes, selecting the first visible row.
    fn new(nodes: Vec<TreeNode>) -> Self {
        let mut s = Self {
            nodes,
            visible: Vec::new(),
            list_state: ListState::default(),
        };
        s.rebuild_visible();
        if !s.visible.is_empty() {
            s.list_state.select(Some(0));
        }
        s
    }

    /// Recomputes the flattened list of visible rows after an expand/collapse.
    fn rebuild_visible(&mut self) {
        self.visible.clear();
        let roots: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| self.nodes[i].parent.is_none())
            .collect();
        for &root in &roots {
            self.collect_visible(root);
        }
    }

    /// Appends `idx` and (when expanded) its subtree to `visible`, pre-order.
    fn collect_visible(&mut self, idx: usize) {
        self.visible.push(idx);
        if self.nodes[idx].expanded {
            let children: Vec<usize> = self.nodes[idx].children.clone();
            for child in children {
                self.collect_visible(child);
            }
        }
    }

    /// Returns the arena index of the currently selected node, if any.
    fn selected_node(&self) -> Option<usize> {
        self.list_state
            .selected()
            .and_then(|i| self.visible.get(i).copied())
    }

    /// Moves the selection one visible row down (clamped at the end).
    fn move_down(&mut self) {
        if let Some(sel) = self.list_state.selected() {
            if sel + 1 < self.visible.len() {
                self.list_state.select(Some(sel + 1));
            }
        }
    }

    /// Moves the selection one visible row up (clamped at the start).
    fn move_up(&mut self) {
        if let Some(sel) = self.list_state.selected() {
            if sel > 0 {
                self.list_state.select(Some(sel - 1));
            }
        }
    }

    /// Toggles expansion of the selected node (no-op on leaves), keeping the
    /// selection in bounds after the visible row count changes.
    fn toggle_expand(&mut self) {
        if let Some(node_idx) = self.selected_node() {
            if !self.nodes[node_idx].children.is_empty() {
                self.nodes[node_idx].expanded = !self.nodes[node_idx].expanded;
                let sel_pos = self.list_state.selected();
                self.rebuild_visible();
                // Keep selection within bounds.
                if let Some(pos) = sel_pos {
                    if pos >= self.visible.len() {
                        self.list_state
                            .select(Some(self.visible.len().saturating_sub(1)));
                    } else {
                        self.list_state.select(Some(pos));
                    }
                }
            }
        }
    }
}

/// All mutable UI state for the browser, rebuilt once from the index.
///
/// The Functions and Options tabs are three-pane (tree, list, detail) with
/// the focused pane tracked by `func_pane`/`opt_pane`; Language and
/// Packages are two-pane. The search overlay state is shared across tabs.
struct App {
    tab: Tab,
    // Tab 1: Language — left chapter/topic tree, right content
    lang_tree: TreeState,
    // Tab 2: Functions — left module tree, middle list, right detail
    func_tree: TreeState,
    func_list: Vec<usize>,
    func_list_state: ListState,
    func_pane: u8, // 0=tree, 1=list, 2=detail
    // Tab 3: Options — left namespace tree, middle list, right detail
    opt_tree: TreeState,
    opt_list: Vec<usize>,
    opt_list_state: ListState,
    opt_pane: u8, // 0=tree, 1=list, 2=detail
    // Tab 4: Packages — left category tree, right detail
    pkg_tree: TreeState,
    // Search
    searching: bool,
    search_query: String,
    search_results: Vec<(usize, i64)>,
    search_list_state: ListState,
    // Detail scroll
    detail_scroll: u16,
    // Reference to entries
    entries: Vec<DocEntry>,
    // Language data (for content)
    lang_content: Vec<(String, String, String)>, // (chapter, topic, body)
}

impl App {
    /// Builds the initial application state from the index: per-category
    /// navigation trees, the language content table, and the initial
    /// function/option lists derived from the first tree selection.
    fn new(index: &DocIndex) -> Self {
        let entries = index.entries.clone();

        // Build language tree from LanguageRef entries.
        let lang_tree = build_language_tree(&entries);

        // Build language content from static data.
        let lang_content = build_language_content();

        // Build function tree.
        let func_entries: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.category == DocCategory::Function)
            .map(|(i, _)| i)
            .collect();
        let func_tree = build_path_tree(&entries, &func_entries, 1);

        // Build option tree.
        let opt_entries: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.category == DocCategory::ModuleOption)
            .map(|(i, _)| i)
            .collect();
        let opt_tree = build_path_tree(&entries, &opt_entries, 1);

        // Build package tree.
        let pkg_entries: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.category == DocCategory::Package)
            .map(|(i, _)| i)
            .collect();
        let pkg_tree = build_path_tree(&entries, &pkg_entries, 1);

        // Initialize function list from first tree selection.
        let func_list =
            Self::children_entries_for_tree(&func_tree, &entries, DocCategory::Function);
        let mut func_list_state = ListState::default();
        if !func_list.is_empty() {
            func_list_state.select(Some(0));
        }

        let opt_list =
            Self::children_entries_for_tree(&opt_tree, &entries, DocCategory::ModuleOption);
        let mut opt_list_state = ListState::default();
        if !opt_list.is_empty() {
            opt_list_state.select(Some(0));
        }

        App {
            tab: Tab::Language,
            lang_tree,
            func_tree,
            func_list,
            func_list_state,
            func_pane: 0,
            opt_tree,
            opt_list,
            opt_list_state,
            opt_pane: 0,
            pkg_tree,
            searching: false,
            search_query: String::new(),
            search_results: Vec::new(),
            search_list_state: ListState::default(),
            detail_scroll: 0,
            entries,
            lang_content,
        }
    }

    /// Returns the entry indices of all leaves under the tree's selection.
    fn children_entries_for_tree(
        tree: &TreeState,
        entries: &[DocEntry],
        _cat: DocCategory,
    ) -> Vec<usize> {
        if let Some(node_idx) = tree.selected_node() {
            collect_leaf_entries(&tree.nodes, node_idx, entries)
        } else {
            Vec::new()
        }
    }

    /// Refreshes the middle function list after a tree selection change.
    fn update_func_list(&mut self) {
        self.func_list =
            Self::children_entries_for_tree(&self.func_tree, &self.entries, DocCategory::Function);
        self.func_list_state = ListState::default();
        if !self.func_list.is_empty() {
            self.func_list_state.select(Some(0));
        }
        self.detail_scroll = 0;
    }

    /// Refreshes the middle option list after a tree selection change.
    fn update_opt_list(&mut self) {
        self.opt_list = Self::children_entries_for_tree(
            &self.opt_tree,
            &self.entries,
            DocCategory::ModuleOption,
        );
        self.opt_list_state = ListState::default();
        if !self.opt_list.is_empty() {
            self.opt_list_state.select(Some(0));
        }
        self.detail_scroll = 0;
    }

    /// Returns the entry selected in the Functions list, if any.
    fn selected_func_entry(&self) -> Option<&DocEntry> {
        self.func_list_state
            .selected()
            .and_then(|i| self.func_list.get(i))
            .and_then(|&idx| self.entries.get(idx))
    }

    /// Returns the entry selected in the Options list, if any.
    fn selected_opt_entry(&self) -> Option<&DocEntry> {
        self.opt_list_state
            .selected()
            .and_then(|i| self.opt_list.get(i))
            .and_then(|&idx| self.entries.get(idx))
    }

    /// Returns the entry for the leaf selected in the Packages tree, if any.
    fn selected_pkg_entry(&self) -> Option<&DocEntry> {
        self.pkg_tree
            .selected_node()
            .and_then(|nid| self.pkg_tree.nodes[nid].entry_idx)
            .and_then(|idx| self.entries.get(idx))
    }

    /// Returns the `(chapter, topic, body)` to display on the Language tab.
    /// Selecting a chapter shows its first topic's content.
    fn selected_lang_content(&self) -> Option<&(String, String, String)> {
        self.lang_tree.selected_node().and_then(|nid| {
            let node = &self.lang_tree.nodes[nid];
            if node.entry_idx.is_some() {
                // Leaf node — find matching content.
                let parent_idx = node.parent?;
                let chapter_name = &self.lang_tree.nodes[parent_idx].label;
                self.lang_content
                    .iter()
                    .find(|(ch, tp, _)| ch == chapter_name && tp == &node.label)
            } else if node.children.is_empty() {
                None
            } else {
                // Chapter node — show first child's content.
                let first_child = *node.children.first()?;
                let child_node = &self.lang_tree.nodes[first_child];
                self.lang_content
                    .iter()
                    .find(|(ch, tp, _)| ch == &node.label && tp == &child_node.label)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tree construction helpers
// ---------------------------------------------------------------------------

/// Builds the Language tab's chapter/topic tree from the static chapter
/// data, linking each topic to its `LanguageRef` entry when one exists.
fn build_language_tree(entries: &[DocEntry]) -> TreeState {
    use crate::data::language::chapters;

    let mut nodes: Vec<TreeNode> = Vec::new();

    for chapter in chapters() {
        let chapter_idx = nodes.len();
        nodes.push(TreeNode {
            label: chapter.name.to_string(),
            depth: 0,
            expanded: true,
            children: Vec::new(),
            entry_idx: None,
            parent: None,
        });

        for topic in chapter.topics {
            let topic_idx = nodes.len();
            // Find matching DocEntry if it exists.
            let entry_idx = entries.iter().position(|e| {
                e.category == DocCategory::LanguageRef && e.path.ends_with(topic.name)
            });
            nodes.push(TreeNode {
                label: topic.name.to_string(),
                depth: 1,
                expanded: false,
                children: Vec::new(),
                entry_idx,
                parent: Some(chapter_idx),
            });
            nodes[chapter_idx].children.push(topic_idx);
        }
    }

    TreeState::new(nodes)
}

/// Flattens the static language data into `(chapter, topic, body)` rows.
fn build_language_content() -> Vec<(String, String, String)> {
    use crate::data::language::chapters;
    let mut content = Vec::new();
    for chapter in chapters() {
        for topic in chapter.topics {
            content.push((
                chapter.name.to_string(),
                topic.name.to_string(),
                topic.body.to_string(),
            ));
        }
    }
    content
}

/// Builds a navigation tree from the dotted paths of the given entries.
///
/// Each path component becomes a node, shared prefixes are merged, leaves
/// point back at their entry, and nodes shallower than `split_depth` start
/// expanded. Entries are sorted by path so sibling order is stable.
fn build_path_tree(entries: &[DocEntry], indices: &[usize], split_depth: usize) -> TreeState {
    struct Builder {
        nodes: Vec<TreeNode>,
        default_expand_depth: usize,
    }

    impl Builder {
        fn get_or_create(&mut self, parent: Option<usize>, label: &str, depth: usize) -> usize {
            // Check if already exists under parent.
            if let Some(p) = parent {
                for &child in &self.nodes[p].children {
                    if self.nodes[child].label == label {
                        return child;
                    }
                }
            } else {
                for (i, n) in self.nodes.iter().enumerate() {
                    if n.parent.is_none() && n.label == label {
                        return i;
                    }
                }
            }

            let idx = self.nodes.len();
            self.nodes.push(TreeNode {
                label: label.to_string(),
                depth,
                expanded: depth < self.default_expand_depth,
                children: Vec::new(),
                entry_idx: None,
                parent,
            });
            if let Some(p) = parent {
                self.nodes[p].children.push(idx);
            }
            idx
        }
    }

    // Sort entries by path for consistent ordering.
    let mut sorted: Vec<usize> = indices.to_vec();
    sorted.sort_by(|&a, &b| entries[a].path.cmp(&entries[b].path));

    let mut builder = Builder {
        nodes: Vec::new(),
        default_expand_depth: split_depth,
    };

    for &entry_idx in &sorted {
        let path = &entries[entry_idx].path;
        let parts: Vec<&str> = path.split('.').collect();

        let mut parent: Option<usize> = None;
        for (depth, &part) in parts.iter().enumerate() {
            let is_leaf = depth == parts.len() - 1;
            let node_idx = builder.get_or_create(parent, part, depth);
            if is_leaf {
                builder.nodes[node_idx].entry_idx = Some(entry_idx);
            }
            parent = Some(node_idx);
        }
    }

    TreeState::new(builder.nodes)
}

/// Collects the entry indices of all leaves in the subtree at `node_idx`.
fn collect_leaf_entries(nodes: &[TreeNode], node_idx: usize, _entries: &[DocEntry]) -> Vec<usize> {
    let mut result = Vec::new();
    collect_leaves_recursive(nodes, node_idx, &mut result);
    result
}

/// Depth-first helper for [`collect_leaf_entries`].
fn collect_leaves_recursive(nodes: &[TreeNode], idx: usize, result: &mut Vec<usize>) {
    if let Some(entry_idx) = nodes[idx].entry_idx {
        result.push(entry_idx);
    }
    for &child in &nodes[idx].children {
        collect_leaves_recursive(nodes, child, result);
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Draw/input loop: renders a frame, then blocks on the next key event.
///
/// While the search overlay is open it captures all keys (Esc cancels,
/// Enter jumps to the selected result); otherwise keys map to tab switches,
/// navigation, pane focus, detail scrolling, and quit (`q` or Ctrl+C).
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    index: &DocIndex,
) -> anyhow::Result<()> {
    let mut app = App::new(index);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            // Search mode captures most keys.
            if app.searching {
                match key.code {
                    KeyCode::Esc => {
                        app.searching = false;
                        app.search_query.clear();
                        app.search_results.clear();
                    }
                    KeyCode::Enter => {
                        // Navigate to selected search result.
                        if let Some(sel) = app.search_list_state.selected() {
                            if let Some(&(entry_idx, _)) = app.search_results.get(sel) {
                                navigate_to_entry(&mut app, entry_idx);
                            }
                        }
                        app.searching = false;
                        app.search_query.clear();
                        app.search_results.clear();
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                        update_search(&mut app);
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                        update_search(&mut app);
                    }
                    KeyCode::Down => {
                        if let Some(sel) = app.search_list_state.selected() {
                            if sel + 1 < app.search_results.len() {
                                app.search_list_state.select(Some(sel + 1));
                            }
                        }
                    }
                    KeyCode::Up => {
                        if let Some(sel) = app.search_list_state.selected() {
                            if sel > 0 {
                                app.search_list_state.select(Some(sel - 1));
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }

            // Ctrl+C always quits.
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                break;
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('1') => {
                    app.tab = Tab::Language;
                    app.detail_scroll = 0;
                }
                KeyCode::Char('2') => {
                    app.tab = Tab::Functions;
                    app.detail_scroll = 0;
                }
                KeyCode::Char('3') => {
                    app.tab = Tab::Options;
                    app.detail_scroll = 0;
                }
                KeyCode::Char('4') => {
                    app.tab = Tab::Packages;
                    app.detail_scroll = 0;
                }
                KeyCode::Char('/') => {
                    app.searching = true;
                    app.search_query.clear();
                    app.search_results.clear();
                    app.search_list_state = ListState::default();
                }
                KeyCode::Char('j') | KeyCode::Down => handle_nav_down(&mut app),
                KeyCode::Char('k') | KeyCode::Up => handle_nav_up(&mut app),
                KeyCode::Enter => handle_enter(&mut app),
                KeyCode::Tab => handle_tab_cycle(&mut app),
                KeyCode::Char('h') | KeyCode::Left => handle_pane_left(&mut app),
                KeyCode::Char('l') | KeyCode::Right => handle_pane_right(&mut app),
                // Scroll detail content.
                KeyCode::Char('d') => {
                    app.detail_scroll = app.detail_scroll.saturating_add(5);
                }
                KeyCode::Char('u') => {
                    app.detail_scroll = app.detail_scroll.saturating_sub(5);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Re-runs the fuzzy search for the current query, keeping the top 20 hits.
fn update_search(app: &mut App) {
    app.search_results = fuzzy_search(&app.entries, &app.search_query);
    app.search_results.truncate(20);
    if !app.search_results.is_empty() {
        app.search_list_state.select(Some(0));
    } else {
        app.search_list_state.select(None);
    }
}

/// Jumps to the tab that owns a search result's category.
///
/// Currently only switches tabs (focusing the list pane where relevant);
/// it does not move the tree/list selection to the specific entry.
fn navigate_to_entry(app: &mut App, entry_idx: usize) {
    let entry = &app.entries[entry_idx];
    match entry.category {
        DocCategory::LanguageRef => app.tab = Tab::Language,
        DocCategory::Function => {
            app.tab = Tab::Functions;
            app.func_pane = 1;
        }
        DocCategory::ModuleOption => {
            app.tab = Tab::Options;
            app.opt_pane = 1;
        }
        DocCategory::Package => app.tab = Tab::Packages,
        DocCategory::Type => {
            app.tab = Tab::Functions;
            app.func_pane = 1;
        }
    }
    app.detail_scroll = 0;
}

/// Handles `j`/Down for the focused pane of the active tab.
fn handle_nav_down(app: &mut App) {
    match app.tab {
        Tab::Language => app.lang_tree.move_down(),
        Tab::Functions => match app.func_pane {
            0 => {
                app.func_tree.move_down();
                app.update_func_list();
            }
            1 => {
                if let Some(sel) = app.func_list_state.selected() {
                    if sel + 1 < app.func_list.len() {
                        app.func_list_state.select(Some(sel + 1));
                        app.detail_scroll = 0;
                    }
                }
            }
            _ => app.detail_scroll = app.detail_scroll.saturating_add(1),
        },
        Tab::Options => match app.opt_pane {
            0 => {
                app.opt_tree.move_down();
                app.update_opt_list();
            }
            1 => {
                if let Some(sel) = app.opt_list_state.selected() {
                    if sel + 1 < app.opt_list.len() {
                        app.opt_list_state.select(Some(sel + 1));
                        app.detail_scroll = 0;
                    }
                }
            }
            _ => app.detail_scroll = app.detail_scroll.saturating_add(1),
        },
        Tab::Packages => app.pkg_tree.move_down(),
    }
}

/// Handles `k`/Up for the focused pane of the active tab.
fn handle_nav_up(app: &mut App) {
    match app.tab {
        Tab::Language => app.lang_tree.move_up(),
        Tab::Functions => match app.func_pane {
            0 => {
                app.func_tree.move_up();
                app.update_func_list();
            }
            1 => {
                if let Some(sel) = app.func_list_state.selected() {
                    if sel > 0 {
                        app.func_list_state.select(Some(sel - 1));
                        app.detail_scroll = 0;
                    }
                }
            }
            _ => app.detail_scroll = app.detail_scroll.saturating_sub(1),
        },
        Tab::Options => match app.opt_pane {
            0 => {
                app.opt_tree.move_up();
                app.update_opt_list();
            }
            1 => {
                if let Some(sel) = app.opt_list_state.selected() {
                    if sel > 0 {
                        app.opt_list_state.select(Some(sel - 1));
                        app.detail_scroll = 0;
                    }
                }
            }
            _ => app.detail_scroll = app.detail_scroll.saturating_sub(1),
        },
        Tab::Packages => app.pkg_tree.move_up(),
    }
}

/// Handles Enter: expands/collapses the focused tree node.
fn handle_enter(app: &mut App) {
    match app.tab {
        Tab::Language => app.lang_tree.toggle_expand(),
        Tab::Functions => match app.func_pane {
            0 => {
                app.func_tree.toggle_expand();
                app.update_func_list();
            }
            _ => {}
        },
        Tab::Options => match app.opt_pane {
            0 => {
                app.opt_tree.toggle_expand();
                app.update_opt_list();
            }
            _ => {}
        },
        Tab::Packages => app.pkg_tree.toggle_expand(),
    }
}

/// Handles Tab: cycles pane focus on the three-pane tabs.
fn handle_tab_cycle(app: &mut App) {
    match app.tab {
        Tab::Language => {} // 2-pane, tree is the only navigable pane
        Tab::Functions => {
            app.func_pane = (app.func_pane + 1) % 3;
            app.detail_scroll = 0;
        }
        Tab::Options => {
            app.opt_pane = (app.opt_pane + 1) % 3;
            app.detail_scroll = 0;
        }
        Tab::Packages => {} // 2-pane
    }
}

/// Handles `h`/Left: moves pane focus one pane to the left.
fn handle_pane_left(app: &mut App) {
    match app.tab {
        Tab::Functions => {
            if app.func_pane > 0 {
                app.func_pane -= 1;
                app.detail_scroll = 0;
            }
        }
        Tab::Options => {
            if app.opt_pane > 0 {
                app.opt_pane -= 1;
                app.detail_scroll = 0;
            }
        }
        _ => {}
    }
}

/// Handles `l`/Right: moves pane focus one pane to the right.
fn handle_pane_right(app: &mut App) {
    match app.tab {
        Tab::Functions => {
            if app.func_pane < 2 {
                app.func_pane += 1;
                app.detail_scroll = 0;
            }
        }
        Tab::Options => {
            if app.opt_pane < 2 {
                app.opt_pane += 1;
                app.detail_scroll = 0;
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// Renders one frame: tab bar, active tab content, status bar, and the
/// search overlay when open.
fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Main layout: tab bar, content, status bar.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(1),    // content
            Constraint::Length(1), // status bar
        ])
        .split(size);

    draw_tab_bar(f, app, chunks[0]);
    draw_content(f, app, chunks[1]);
    draw_status_bar(f, app, chunks[2]);

    if app.searching {
        draw_search_overlay(f, app, size);
    }
}

/// Renders the numbered tab bar with the active tab highlighted.
fn draw_tab_bar(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let num = format!("{}", i + 1);
            Line::from(vec![
                Span::styled(num, Style::default().bold()),
                Span::raw(" "),
                Span::raw(t.title()),
            ])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" aos doc "))
        .select(app.tab.index())
        .highlight_style(Style::default().fg(ratatui::style::Color::Cyan).bold());

    f.render_widget(tabs, area);
}

/// Dispatches content rendering to the active tab's draw function.
fn draw_content(f: &mut Frame, app: &mut App, area: Rect) {
    match app.tab {
        Tab::Language => draw_language_tab(f, app, area),
        Tab::Functions => draw_functions_tab(f, app, area),
        Tab::Options => draw_options_tab(f, app, area),
        Tab::Packages => draw_packages_tab(f, app, area),
    }
}

/// Renders the one-line key help appropriate to the active tab.
fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let help = match app.tab {
        Tab::Language => "j/k:navigate  Enter:expand/collapse  /:search  q:quit",
        Tab::Functions | Tab::Options => {
            "j/k:navigate  Tab/h/l:switch pane  Enter:expand  d/u:scroll  /:search  q:quit"
        }
        Tab::Packages => "j/k:navigate  Enter:expand/collapse  d/u:scroll  /:search  q:quit",
    };

    let bar = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(help, Style::default().dim()),
    ]));
    f.render_widget(bar, area);
}

// ---------------------------------------------------------------------------
// Tab 1: Language
// ---------------------------------------------------------------------------

/// Renders the Language tab: chapter/topic tree (left), rendered markdown
/// content (right).
fn draw_language_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // Left: chapter/topic tree.
    let items: Vec<ListItem> = app
        .lang_tree
        .visible
        .iter()
        .map(|&nid| {
            let node = &app.lang_tree.nodes[nid];
            let indent = "  ".repeat(node.depth);
            let arrow = if !node.children.is_empty() {
                if node.expanded { "v " } else { "> " }
            } else {
                "  "
            };
            ListItem::new(format!("{indent}{arrow}{}", node.label))
        })
        .collect();

    let tree_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Chapters "))
        .highlight_style(
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(tree_list, chunks[0], &mut app.lang_tree.list_state);

    // Right: content.
    let content = if let Some((chapter, topic, body)) = app.selected_lang_content() {
        let mut lines = vec![
            Line::from(Span::styled(
                format!("{chapter} > {topic}"),
                Style::default().bold(),
            )),
            Line::from(""),
        ];
        lines.extend(render_markdown_lines(body));
        Text::from(lines)
    } else {
        Text::from("Select a topic from the left panel.")
    };

    let para = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Content "))
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(para, chunks[1]);
}

// ---------------------------------------------------------------------------
// Tab 2: Functions
// ---------------------------------------------------------------------------

/// Renders the Functions tab: module tree, function list (with abbreviated
/// return types), and entry detail. The focused pane gets a cyan border.
fn draw_functions_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Percentage(50),
        ])
        .split(area);

    // Left: module tree.
    let tree_border_style = if app.func_pane == 0 {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let items: Vec<ListItem> = app
        .func_tree
        .visible
        .iter()
        .map(|&nid| {
            let node = &app.func_tree.nodes[nid];
            let indent = "  ".repeat(node.depth);
            let arrow = if !node.children.is_empty() {
                if node.expanded { "v " } else { "> " }
            } else {
                "  "
            };
            ListItem::new(format!("{indent}{arrow}{}", node.label))
        })
        .collect();

    let tree_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Modules ")
                .border_style(tree_border_style),
        )
        .highlight_style(
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(tree_list, chunks[0], &mut app.func_tree.list_state);

    // Middle: function list.
    let list_border_style = if app.func_pane == 1 {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let func_items: Vec<ListItem> = app
        .func_list
        .iter()
        .map(|&idx| {
            let entry = &app.entries[idx];
            let name = entry.path.rsplit('.').next().unwrap_or(&entry.path);
            let type_abbrev = entry
                .type_sig
                .as_ref()
                .map(|t| {
                    // Show abbreviated return type.
                    if let Some(pos) = t.rfind("->") {
                        t[pos + 2..].trim().to_string()
                    } else {
                        t.clone()
                    }
                })
                .unwrap_or_default();
            let display = if type_abbrev.is_empty() {
                name.to_string()
            } else {
                format!("{name}  {type_abbrev}")
            };
            ListItem::new(display)
        })
        .collect();

    let func_list_widget = List::new(func_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Functions ")
                .border_style(list_border_style),
        )
        .highlight_style(
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(func_list_widget, chunks[1], &mut app.func_list_state);

    // Right: function detail.
    let detail_border_style = if app.func_pane == 2 {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let detail = if let Some(entry) = app.selected_func_entry() {
        render_entry_detail(entry)
    } else {
        Text::from("Select a function.")
    };

    let detail_widget = Paragraph::new(detail)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Detail ")
                .border_style(detail_border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(detail_widget, chunks[2]);
}

// ---------------------------------------------------------------------------
// Tab 3: Options
// ---------------------------------------------------------------------------

/// Renders the Options tab: namespace tree, option list (with type names),
/// and option detail. The focused pane gets a cyan border.
fn draw_options_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Percentage(50),
        ])
        .split(area);

    // Left: namespace tree.
    let tree_border_style = if app.opt_pane == 0 {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let items: Vec<ListItem> = app
        .opt_tree
        .visible
        .iter()
        .map(|&nid| {
            let node = &app.opt_tree.nodes[nid];
            let indent = "  ".repeat(node.depth);
            let arrow = if !node.children.is_empty() {
                if node.expanded { "v " } else { "> " }
            } else {
                "  "
            };
            ListItem::new(format!("{indent}{arrow}{}", node.label))
        })
        .collect();

    let tree_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Namespaces ")
                .border_style(tree_border_style),
        )
        .highlight_style(
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(tree_list, chunks[0], &mut app.opt_tree.list_state);

    // Middle: option list.
    let list_border_style = if app.opt_pane == 1 {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let opt_items: Vec<ListItem> = app
        .opt_list
        .iter()
        .map(|&idx| {
            let entry = &app.entries[idx];
            let name = entry.path.rsplit('.').next().unwrap_or(&entry.path);
            let type_name = entry.type_sig.as_deref().unwrap_or("");
            let display = if type_name.is_empty() {
                name.to_string()
            } else {
                format!("{name}  {type_name}")
            };
            ListItem::new(display)
        })
        .collect();

    let opt_list_widget = List::new(opt_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Options ")
                .border_style(list_border_style),
        )
        .highlight_style(
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(opt_list_widget, chunks[1], &mut app.opt_list_state);

    // Right: option detail.
    let detail_border_style = if app.opt_pane == 2 {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let detail = if let Some(entry) = app.selected_opt_entry() {
        render_option_detail(entry)
    } else {
        Text::from("Select an option.")
    };

    let detail_widget = Paragraph::new(detail)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Detail ")
                .border_style(detail_border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(detail_widget, chunks[2]);
}

// ---------------------------------------------------------------------------
// Tab 4: Packages
// ---------------------------------------------------------------------------

/// Renders the Packages tab: package tree (left), package detail (right).
fn draw_packages_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // Left: category tree.
    let items: Vec<ListItem> = app
        .pkg_tree
        .visible
        .iter()
        .map(|&nid| {
            let node = &app.pkg_tree.nodes[nid];
            let indent = "  ".repeat(node.depth);
            let arrow = if !node.children.is_empty() {
                if node.expanded { "v " } else { "> " }
            } else {
                "  "
            };
            ListItem::new(format!("{indent}{arrow}{}", node.label))
        })
        .collect();

    let tree_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Packages "))
        .highlight_style(
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(tree_list, chunks[0], &mut app.pkg_tree.list_state);

    // Right: package detail.
    let detail = if let Some(entry) = app.selected_pkg_entry() {
        render_package_detail(entry)
    } else {
        Text::from("Select a package from the left panel.")
    };

    let detail_widget = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(detail_widget, chunks[1]);
}

// ---------------------------------------------------------------------------
// Search overlay
// ---------------------------------------------------------------------------

/// Renders the search overlay anchored to the bottom of the screen, showing
/// the query line and scored results with the selection highlighted.
fn draw_search_overlay(f: &mut Frame, app: &mut App, area: Rect) {
    // Search overlay at the bottom of the screen.
    let height = (app.search_results.len() as u16 + 3)
        .min(area.height / 2)
        .max(3);
    let overlay_area = Rect {
        x: area.x + 1,
        y: area.y + area.height - height - 1,
        width: area.width.saturating_sub(2),
        height,
    };

    f.render_widget(Clear, overlay_area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("/ ", Style::default().bold()),
        Span::raw(app.search_query.clone()),
        Span::styled("_", Style::default().dim()),
    ]));

    for (i, &(entry_idx, score)) in app.search_results.iter().enumerate() {
        let entry = &app.entries[entry_idx];
        let style = if app.search_list_state.selected() == Some(i) {
            Style::default().fg(ratatui::style::Color::Cyan).bold()
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("[{}] ", entry.category), Style::default().dim()),
            Span::styled(entry.path.clone(), style),
            Span::styled(format!("  ({score})"), Style::default().dim()),
        ]));
    }

    let search_widget = Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title(" Search "));

    f.render_widget(search_widget, overlay_area);
}

// ---------------------------------------------------------------------------
// Detail rendering
// ---------------------------------------------------------------------------

/// Renders a function/type entry as styled text: path, type signature,
/// summary, body, parameters, examples, see-also, and source location.
fn render_entry_detail(entry: &DocEntry) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();

    // Title.
    lines.push(Line::from(Span::styled(
        entry.path.clone(),
        Style::default().bold(),
    )));
    lines.push(Line::from(""));

    // Type signature.
    if let Some(ref sig) = entry.type_sig {
        lines.push(Line::from(Span::styled("Type:", Style::default().bold())));
        lines.push(Line::from(Span::styled(
            format!("  {sig}"),
            Style::default().fg(ratatui::style::Color::Green),
        )));
        lines.push(Line::from(""));
    }

    // The body includes the summary as its first paragraph, so render only
    // one source. Prefer the body because it preserves inline formatting.
    if !entry.body.is_empty() {
        lines.extend(render_markdown_lines(&entry.body));
        lines.push(Line::from(""));
    } else if !entry.summary.is_empty() {
        lines.push(Line::from(entry.summary.clone()));
        lines.push(Line::from(""));
    }

    // Parameters.
    if !entry.parameters.is_empty() {
        lines.push(Line::from(Span::styled(
            "Parameters:",
            Style::default().bold(),
        )));
        for (name, desc) in &entry.parameters {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {name}"),
                    Style::default().fg(ratatui::style::Color::Yellow),
                ),
                Span::styled(format!(" - {desc}"), Style::default()),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Examples.
    if !entry.examples.is_empty() {
        lines.push(Line::from(Span::styled(
            "Examples:",
            Style::default().bold(),
        )));
        for example in &entry.examples {
            for line in example.lines() {
                lines.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().dim(),
                )));
            }
            lines.push(Line::from(""));
        }
    }

    // See also.
    if !entry.see_also.is_empty() {
        lines.push(Line::from(Span::styled(
            "See also:",
            Style::default().bold(),
        )));
        lines.push(Line::from(format!("  {}", entry.see_also.join(", "))));
        lines.push(Line::from(""));
    }

    // Source.
    if let Some(ref src) = entry.source_file {
        let loc = if let Some(line) = entry.source_line {
            format!("{src}:{line}")
        } else {
            src.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("Source: ", Style::default().bold()),
            Span::styled(loc, Style::default().dim()),
        ]));
    }

    Text::from(lines)
}

/// Renders a module option entry as styled text: path, type, default,
/// description, examples, see-also, and the declaring file.
fn render_option_detail(entry: &DocEntry) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();

    // Title.
    lines.push(Line::from(Span::styled(
        entry.path.clone(),
        Style::default().bold(),
    )));
    lines.push(Line::from(""));

    // Type.
    if let Some(ref sig) = entry.type_sig {
        lines.push(Line::from(vec![
            Span::styled("Type: ", Style::default().bold()),
            Span::styled(
                sig.clone(),
                Style::default().fg(ratatui::style::Color::Green),
            ),
        ]));
    }

    // Default.
    if let Some(ref default) = entry.default {
        lines.push(Line::from(vec![
            Span::styled("Default: ", Style::default().bold()),
            Span::raw(default.clone()),
        ]));
    }
    lines.push(Line::from(""));

    // The body includes the summary as its first paragraph, so render only
    // one source. Prefer the body because it preserves inline formatting.
    if !entry.body.is_empty() {
        lines.extend(render_markdown_lines(&entry.body));
        lines.push(Line::from(""));
    } else if !entry.summary.is_empty() {
        lines.push(Line::from(entry.summary.clone()));
        lines.push(Line::from(""));
    }

    // Examples.
    if !entry.examples.is_empty() {
        lines.push(Line::from(Span::styled(
            "Examples:",
            Style::default().bold(),
        )));
        for example in &entry.examples {
            for line in example.lines() {
                lines.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().dim(),
                )));
            }
            lines.push(Line::from(""));
        }
    }

    // See also.
    if !entry.see_also.is_empty() {
        lines.push(Line::from(Span::styled(
            "See also:",
            Style::default().bold(),
        )));
        lines.push(Line::from(format!("  {}", entry.see_also.join(", "))));
        lines.push(Line::from(""));
    }

    // Declared in.
    if let Some(ref src) = entry.source_file {
        let loc = if let Some(line) = entry.source_line {
            format!("{src}:{line}")
        } else {
            src.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("Declared in: ", Style::default().bold()),
            Span::styled(loc, Style::default().dim()),
        ]));
    }

    Text::from(lines)
}

/// Renders a package entry as styled text: name, version, description, and
/// any dependency/URL metadata recorded in the entry's `extra` map.
fn render_package_detail(entry: &DocEntry) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();

    // Title.
    let name = entry.path.rsplit('.').next().unwrap_or(&entry.path);
    lines.push(Line::from(Span::styled(
        name.to_string(),
        Style::default().bold(),
    )));
    lines.push(Line::from(""));

    // Version.
    if let Some(version) = entry.extra.get("version") {
        lines.push(Line::from(vec![
            Span::styled("Version: ", Style::default().bold()),
            Span::raw(version.clone()),
        ]));
    }

    // The body includes the summary as its first paragraph, so render only
    // one source. Prefer the body because it preserves inline formatting.
    if !entry.body.is_empty() {
        lines.push(Line::from(""));
        lines.extend(render_markdown_lines(&entry.body));
    } else if !entry.summary.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(entry.summary.clone()));
    }
    lines.push(Line::from(""));

    // Build deps.
    if let Some(deps) = entry.extra.get("buildDeps") {
        lines.push(Line::from(Span::styled(
            "Build dependencies:",
            Style::default().bold(),
        )));
        for dep in deps.split(", ") {
            lines.push(Line::from(format!("  - {dep}")));
        }
        lines.push(Line::from(""));
    }

    // Runtime deps.
    if let Some(deps) = entry.extra.get("runtimeDeps") {
        lines.push(Line::from(Span::styled(
            "Runtime dependencies:",
            Style::default().bold(),
        )));
        for dep in deps.split(", ") {
            lines.push(Line::from(format!("  - {dep}")));
        }
        lines.push(Line::from(""));
    }

    // Source file.
    if let Some(ref src) = entry.source_file {
        lines.push(Line::from(vec![
            Span::styled("Source: ", Style::default().bold()),
            Span::styled(src.clone(), Style::default().dim()),
        ]));
    }

    // Download URLs.
    if let Some(urls) = entry.extra.get("urls") {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Download URLs:",
            Style::default().bold(),
        )));
        for url in urls.split(' ') {
            lines.push(Line::from(Span::styled(
                format!("  {url}"),
                Style::default().dim(),
            )));
        }
    }

    Text::from(lines)
}

// ---------------------------------------------------------------------------
// Simple markdown-to-styled-text renderer
// ---------------------------------------------------------------------------

/// Converts markdown to styled lines: `#`/`##` headings become bold,
/// fenced code blocks are dimmed and indented, full-line `**bold**` is
/// bolded, and inline backtick spans are highlighted.
fn render_markdown_lines(text: &str) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut in_code_block = false;

    for line in text.lines() {
        let trimmed = line.trim();

        // Code block fences.
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            if in_code_block {
                lines.push(Line::from(""));
            }
            continue;
        }

        if in_code_block {
            lines.push(Line::from(Span::styled(
                format!("  {line}"),
                Style::default().dim(),
            )));
            continue;
        }

        // Headings.
        if trimmed.starts_with("## ") {
            lines.push(Line::from(Span::styled(
                trimmed[3..].to_string(),
                Style::default().bold().underlined(),
            )));
            continue;
        }
        if trimmed.starts_with("# ") {
            lines.push(Line::from(Span::styled(
                trimmed[2..].to_string(),
                Style::default().bold(),
            )));
            continue;
        }

        // Bold text (**...**).
        if trimmed.starts_with("**") && trimmed.ends_with("**") && trimmed.len() > 4 {
            lines.push(Line::from(Span::styled(
                trimmed[2..trimmed.len() - 2].to_string(),
                Style::default().bold(),
            )));
            continue;
        }

        // Regular line with inline backtick highlighting.
        let spans = render_inline_code(line);
        lines.push(Line::from(spans));
    }

    lines
}

/// Splits a line into spans, coloring `` `code` `` segments yellow.
/// An unmatched backtick is emitted literally.
fn render_inline_code(text: &str) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut rest = text;

    while let Some(start) = rest.find('`') {
        if start > 0 {
            spans.push(Span::raw(rest[..start].to_string()));
        }
        let after_tick = &rest[start + 1..];
        if let Some(end) = after_tick.find('`') {
            spans.push(Span::styled(
                after_tick[..end].to_string(),
                Style::default().fg(ratatui::style::Color::Yellow),
            ));
            rest = &after_tick[end + 1..];
        } else {
            // No closing backtick — just output the rest.
            spans.push(Span::raw(rest[start..].to_string()));
            rest = "";
            break;
        }
    }

    if !rest.is_empty() {
        spans.push(Span::raw(rest.to_string()));
    }

    if spans.is_empty() {
        spans.push(Span::raw(String::new()));
    }

    spans
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ratatui::style::Color;

    use super::*;

    fn documented_entry(category: DocCategory) -> DocEntry {
        DocEntry {
            path: "test.entry".to_string(),
            category,
            summary: "Returns `value`.".to_string(),
            body: "Returns `value`.\n\nMore detail.".to_string(),
            type_sig: None,
            default: None,
            examples: Vec::new(),
            see_also: Vec::new(),
            parameters: Vec::new(),
            source_file: None,
            source_line: None,
            section: None,
            extra: BTreeMap::new(),
        }
    }

    fn assert_summary_rendered_once(text: &Text<'_>) {
        let rendered_lines: Vec<String> = text
            .lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect()
            })
            .collect();

        assert_eq!(
            rendered_lines
                .iter()
                .filter(|line| line.replace('`', "") == "Returns value.")
                .count(),
            1
        );
        assert!(text.lines.iter().any(|line| {
            line.spans.iter().any(|span| {
                span.content.as_ref() == "value" && span.style.fg == Some(Color::Yellow)
            })
        }));
    }

    #[test]
    fn detail_views_render_formatted_summaries_once() {
        let function = documented_entry(DocCategory::Function);
        let option = documented_entry(DocCategory::ModuleOption);
        let package = documented_entry(DocCategory::Package);

        assert_summary_rendered_once(&render_entry_detail(&function));
        assert_summary_rendered_once(&render_option_detail(&option));
        assert_summary_rendered_once(&render_package_detail(&package));
    }
}
