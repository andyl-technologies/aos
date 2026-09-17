# Uninitialized array elements retain an empty string after scalar reads.
# GCC's option generator compares an entry before appending warning names.
BEGIN {
    if (warnings["enabled"] != "")
        exit 1

    warnings["enabled"] = warnings["enabled"] "Wextra;"
    if (warnings["enabled"] != "Wextra;")
        exit 2

    number = values["unset"] + 0
    if (number != 0 || (values["unset"] "suffix") != "suffix")
        exit 3

    # Array creation and deletion also use the new-element representation.
    nested["parent"]["child"] = 7
    if (nested["parent"]["child"] != 7)
        exit 4

    delete warnings["enabled"]
    if ((warnings["enabled"] "suffix") != "suffix")
        exit 5
}
