//! Read-only full-screen cockpit for local package-maintenance state.

use std::io;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_maintain::discovery::{DiscoverySnapshotV1, UnitDiscovery};
use aos_maintain::identity::RunId;
use aos_maintain::run::PackageUpdateRunV1;
use aos_maintain::workflow::{DiscoveryDecision, RunState};
use crossterm::ExecutableCommand as _;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap};

/// Opens the local cockpit and restores the terminal on every ordinary exit.
pub(super) async fn run(
    runs: Vec<PackageUpdateRunV1>,
    discovery: Option<DiscoverySnapshotV1>,
    selected_run: Option<&RunId>,
) -> Result<()> {
    let selected_run = selected_run.cloned();
    tokio::task::spawn_blocking(move || run_blocking(runs, discovery, selected_run.as_ref()))
        .await
        .context("maintenance cockpit task panicked")?
}

fn run_blocking(
    runs: Vec<PackageUpdateRunV1>,
    discovery: Option<DiscoverySnapshotV1>,
    selected_run: Option<&RunId>,
) -> Result<()> {
    let mut guard = TerminalGuard::enter()?;
    let mut app = App::new(runs, discovery, selected_run);
    loop {
        guard.terminal.draw(|frame| draw(frame, &mut app))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match (key.code, key.modifiers) {
                (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => break,
                (KeyCode::Char('c'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
                    break;
                }
                (KeyCode::Char('1'), _) => app.tab = Tab::Inbox,
                (KeyCode::Char('2'), _) => app.tab = Tab::Runs,
                (KeyCode::Tab | KeyCode::Right | KeyCode::Char('l'), _) => app.next_tab(),
                (KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h'), _) => app.previous_tab(),
                (KeyCode::Down | KeyCode::Char('j'), _) => app.move_selection(1),
                (KeyCode::Up | KeyCode::Char('k'), _) => app.move_selection(-1),
                (KeyCode::PageDown, _) => app.move_selection(10),
                (KeyCode::PageUp, _) => app.move_selection(-10),
                (KeyCode::Home, _) => app.select_first(),
                (KeyCode::End, _) => app.select_last(),
                _ => {}
            }
        }
    }
    Ok(())
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enabling terminal raw mode")?;
        let mut stdout = io::stdout();
        if let Err(error) = stdout.execute(EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error).context("entering alternate screen");
        }
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = disable_raw_mode();
                let _ = io::stdout().execute(LeaveAlternateScreen);
                return Err(error).context("initializing maintenance terminal");
            }
        };
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = self.terminal.backend_mut().execute(LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Tab {
    Inbox,
    Runs,
}

struct App {
    tab: Tab,
    runs: Vec<PackageUpdateRunV1>,
    units: Vec<UnitDiscovery>,
    run_state: ListState,
    inbox_state: ListState,
}

impl App {
    fn new(
        runs: Vec<PackageUpdateRunV1>,
        discovery: Option<DiscoverySnapshotV1>,
        selected_run: Option<&RunId>,
    ) -> Self {
        let units = discovery.map(|value| value.units).unwrap_or_default();
        let mut run_state = ListState::default();
        if !runs.is_empty() {
            let selected = selected_run
                .and_then(|id| runs.iter().position(|run| &run.run_id == id))
                .unwrap_or(0);
            run_state.select(Some(selected));
        }
        let mut inbox_state = ListState::default();
        if !units.is_empty() {
            inbox_state.select(Some(0));
        }
        Self {
            tab: selected_run.map_or(Tab::Inbox, |_| Tab::Runs),
            runs,
            units,
            run_state,
            inbox_state,
        }
    }

    fn next_tab(&mut self) {
        self.tab = match self.tab {
            Tab::Inbox => Tab::Runs,
            Tab::Runs => Tab::Inbox,
        };
    }

    fn previous_tab(&mut self) {
        self.next_tab();
    }

    fn move_selection(&mut self, delta: isize) {
        let (state, length) = match self.tab {
            Tab::Inbox => (&mut self.inbox_state, self.units.len()),
            Tab::Runs => (&mut self.run_state, self.runs.len()),
        };
        if length == 0 {
            return;
        }
        let current = state.selected().unwrap_or(0);
        state.select(Some(current.saturating_add_signed(delta).min(length - 1)));
    }

    fn select_first(&mut self) {
        match self.tab {
            Tab::Inbox => self
                .inbox_state
                .select((!self.units.is_empty()).then_some(0)),
            Tab::Runs => self.run_state.select((!self.runs.is_empty()).then_some(0)),
        }
    }

    fn select_last(&mut self) {
        match self.tab {
            Tab::Inbox => self.inbox_state.select(self.units.len().checked_sub(1)),
            Tab::Runs => self.run_state.select(self.runs.len().checked_sub(1)),
        }
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());
    let selected = match app.tab {
        Tab::Inbox => 0,
        Tab::Runs => 1,
    };
    let tabs = Tabs::new(["1  Update inbox", "2  Active & retained runs"])
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" AOS Maintainer "),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, sections[0]);

    match app.tab {
        Tab::Inbox => draw_inbox(frame, sections[1], app),
        Tab::Runs => draw_runs(frame, sections[1], app),
    }
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" j/k ", Style::default().fg(Color::Cyan)),
        Span::raw("move   "),
        Span::styled(" tab/h/l ", Style::default().fg(Color::Cyan)),
        Span::raw("switch view   "),
        Span::styled(" q ", Style::default().fg(Color::Cyan)),
        Span::raw("quit   read-only local state"),
    ]));
    frame.render_widget(help, sections[2]);
}

fn draw_inbox(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let panes = split_panes(area);
    let items = app
        .units
        .iter()
        .map(|unit| {
            let (symbol, color) = discovery_badge(unit.decision);
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {symbol} "), Style::default().fg(color)),
                Span::raw(unit.unit_id.clone()),
            ]))
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Inbox · {} units ", app.units.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("›");
    frame.render_stateful_widget(list, panes[0], &mut app.inbox_state);

    let detail = app
        .inbox_state
        .selected()
        .and_then(|index| app.units.get(index))
        .map(inbox_detail)
        .unwrap_or_else(|| Text::from("No cached discovery. Run `aos maintain scan`."));
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Selection "))
            .wrap(Wrap { trim: false }),
        panes[1],
    );
}

fn draw_runs(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let panes = split_panes(area);
    let active = app
        .runs
        .iter()
        .filter(|run| !run.state.is_terminal())
        .count();
    let items = app
        .runs
        .iter()
        .map(|run| {
            let (symbol, color) = run_badge(run.state);
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {symbol} "), Style::default().fg(color)),
                Span::raw(short_identity(run.run_id.as_str())),
                Span::styled(
                    format!("  {}", run_state_name(run.state)),
                    Style::default().fg(Color::Gray),
                ),
            ]))
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Runs · {active} active / {} retained ",
            app.runs.len()
        )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("›");
    frame.render_stateful_widget(list, panes[0], &mut app.run_state);

    let detail = app
        .run_state
        .selected()
        .and_then(|index| app.runs.get(index))
        .map(run_detail)
        .unwrap_or_else(|| Text::from("No retained maintenance runs."));
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Run detail "))
            .wrap(Wrap { trim: false }),
        panes[1],
    );
}

fn split_panes(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(43), Constraint::Percentage(57)])
        .split(area)
}

fn inbox_detail(unit: &UnitDiscovery) -> Text<'static> {
    let target = unit
        .components
        .iter()
        .filter_map(|component| component.selected.as_ref())
        .map(|version| version.comparison_version.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Text::from(vec![
        Line::styled(
            unit.unit_id.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        labeled("Decision", discovery_name(unit.decision)),
        labeled("Candidate", if target.is_empty() { "-" } else { &target }),
        labeled("Components", &unit.components.len().to_string()),
        Line::raw(""),
        Line::styled(inbox_hint(unit), Style::default().fg(Color::Cyan)),
    ])
}

fn run_detail(run: &PackageUpdateRunV1) -> Text<'static> {
    let next = next_step(run.state, &run.run_id);
    Text::from(vec![
        Line::styled(
            run.run_id.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        labeled("State", run_state_name(run.state)),
        labeled("Attempt", &run.attempt.to_string()),
        labeled("Branch", &run.branch),
        labeled("Worktree", &run.worktree),
        Line::raw(""),
        Line::styled("Next", Style::default().fg(Color::Gray)),
        Line::raw(next),
    ])
}

fn labeled(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), Style::default().fg(Color::Gray)),
        Span::raw(value.to_string()),
    ])
}

fn inbox_hint(unit: &UnitDiscovery) -> String {
    match unit.decision {
        DiscoveryDecision::UpdateAvailable => format!("aos maintain plan {}", unit.unit_id),
        DiscoveryDecision::Current => "No action needed.".to_string(),
        DiscoveryDecision::Unknown => {
            "Refresh or investigate incomplete upstream evidence.".to_string()
        }
        DiscoveryDecision::Quarantined => {
            "Investigate conflicting upstream identity evidence.".to_string()
        }
    }
}

fn next_step(state: RunState, run: &RunId) -> String {
    let command = match state {
        RunState::WorktreeReady | RunState::Materializing | RunState::PolicyValid => "resume",
        RunState::QuickGated => "accept",
        RunState::Repairing => "repair",
        RunState::CandidateAccepted => "commit",
        RunState::Committed => "test --final",
        RunState::FinalGated => "evidence",
        RunState::ReadyForPr => "prepare-pr",
        RunState::PrPublished | RunState::AwaitingRemoteAuthorization => "observe-pr",
        RunState::MergedObserved => "handoff",
        _ => return "No automatic next action from this state.".to_string(),
    };
    format!("aos maintain {command} {run}")
}

fn short_identity(value: &str) -> String {
    value.chars().take(18).collect()
}

fn discovery_badge(decision: DiscoveryDecision) -> (&'static str, Color) {
    match decision {
        DiscoveryDecision::Current => ("●", Color::Green),
        DiscoveryDecision::UpdateAvailable => ("↑", Color::Cyan),
        DiscoveryDecision::Unknown => ("?", Color::Yellow),
        DiscoveryDecision::Quarantined => ("!", Color::Red),
    }
}

fn run_badge(state: RunState) -> (&'static str, Color) {
    match state {
        RunState::ReleaseHandoff | RunState::NoChange => ("●", Color::Green),
        RunState::BlockedHuman | RunState::Repairing => ("◆", Color::Yellow),
        RunState::Quarantined | RunState::Failed | RunState::Rejected => ("!", Color::Red),
        RunState::Abandoned | RunState::Superseded => ("○", Color::DarkGray),
        _ => ("●", Color::Cyan),
    }
}

fn discovery_name(decision: DiscoveryDecision) -> &'static str {
    match decision {
        DiscoveryDecision::Current => "current",
        DiscoveryDecision::UpdateAvailable => "update available",
        DiscoveryDecision::Unknown => "upstream unknown",
        DiscoveryDecision::Quarantined => "quarantined",
    }
}

fn run_state_name(state: RunState) -> &'static str {
    match state {
        RunState::Observed => "observed",
        RunState::Selected => "selected",
        RunState::Planned => "planned",
        RunState::WorktreeReady => "worktree ready",
        RunState::Materializing => "materializing",
        RunState::PolicyValid => "policy valid",
        RunState::QuickGated => "quick gates passed",
        RunState::Repairing => "repair awaiting review",
        RunState::CandidateAccepted => "candidate accepted",
        RunState::Committed => "candidate committed",
        RunState::FinalGated => "final gates passed",
        RunState::ReadyForPr => "ready for PR",
        RunState::PrPublished => "PR published",
        RunState::AwaitingRemoteAuthorization => "awaiting remote authorization",
        RunState::MergeEligibleObserved => "merge eligible",
        RunState::MergedObserved => "merge observed",
        RunState::ReleaseHandoff => "release handoff",
        RunState::NoChange => "no change",
        RunState::Superseded => "superseded",
        RunState::BlockedHuman => "blocked on maintainer",
        RunState::Quarantined => "quarantined",
        RunState::Rejected => "rejected",
        RunState::Abandoned => "abandoned",
        RunState::Failed => "failed",
    }
}
