# SPDX-License-Identifier: MIT
"""Selects parent-zero x86 Linux construction without retagging legacy output.

The original fixed PC loader, guest assets and board remain source-bound. This
separate root family chooses its lineage before any callback and never turns a
parent17 mechanism receipt into root output. It grants no execution authority.
"""

import importlib.util
from pathlib import Path

import m5


specification = importlib.util.spec_from_file_location(
    "crucible_x86_root_board", Path(__file__).with_name("native-controller-x86-model.py")
)
board = importlib.util.module_from_spec(specification)
specification.loader.exec_module(board)


class X86RootLinuxModel(board.X86LinuxModel):
    """Constructs one explicitly selected no-ingress root at its original cut."""

    selection_schema = "crucible.gem5.x86-linux-root-model.v1"
    model_id = "x86-linux-pc-atomic-root-functional-v1"

    def __init__(self, bootstrap, resource_root):
        selection = bootstrap.get("model")
        if (type(selection) is not dict
                or set(selection) != {"schema", "assets", "configs"}
                or selection["schema"] != self.selection_schema):
            raise ValueError("x86 root construction requires its distinct source selection")
        delegated = dict(bootstrap)
        delegated["model"] = dict(selection, schema="crucible.gem5.x86-linux-model.v1")
        super().__init__(delegated, resource_root)

    def realize(self):
        root = super().realize()
        position = m5.crucibleEventPosition()
        if (position["active"] or position["ordinal"] != "0"
                or position["tick_ordinal"] != "0" or position["tick"] != "0"):
            raise ValueError("x86 root lineage cannot follow modeled execution")
        if not self.terminal.crucibleSetOutputParent(0):
            raise ValueError("x86 root lineage was not selected on the unused native FIFO")
        return root

    def describe_scope(self):
        scope = super().describe_scope()
        scope["model_id"] = self.model_id
        return scope
