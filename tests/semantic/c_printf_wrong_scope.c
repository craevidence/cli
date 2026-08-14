static int printf(const char *value)
{
    return value[0];
}

static int render(char **argv)
{
    return printf(argv[1]);
}

int main(int argc, char **argv)
{
    return argc + render(argv);
}
