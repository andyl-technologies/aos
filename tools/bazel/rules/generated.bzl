"""Runs declared Python generators with an AOS interpreter and input closure."""

def _generator_impl(ctx):
    environment = {
        "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "1", "PYTHONHASHSEED": "0",
    }
    for name, value in ctx.attr.env.items():
        if name in environment or name in ["PATH", "HOME", "LD_LIBRARY_PATH", "PYTHONHOME", "PYTHONPATH"]:
            fail("generator environment cannot override tool discovery: " + name)
        environment[name] = value
    arguments = ctx.actions.args()
    arguments.add(ctx.file.script)
    arguments.add("--inputs")
    arguments.add_all(ctx.files.srcs)
    arguments.add("--outputs")
    arguments.add_all(ctx.outputs.outs)
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = [arguments],
        inputs = depset([ctx.file.script, ctx.file._tool_identity] + ctx.files.srcs),
        outputs = ctx.outputs.outs,
        env = environment,
        mnemonic = "AosPythonGenerate",
        progress_message = "Generating declared sources for %{label}",
    )
    return [DefaultInfo(files = depset(ctx.outputs.outs))]

aos_python_generator = rule(
    implementation = _generator_impl,
    attrs = {
        "script": attr.label(mandatory = True, allow_single_file = True),
        "srcs": attr.label_list(mandatory = True, allow_files = True),
        "outs": attr.output_list(mandatory = True),
        "env": attr.string_dict(),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
)
