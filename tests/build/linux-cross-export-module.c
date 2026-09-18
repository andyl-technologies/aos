extern int aos_cross_exported_symbol(void);

int aos_cross_extension_symbol(void)
{
    return aos_cross_exported_symbol();
}
