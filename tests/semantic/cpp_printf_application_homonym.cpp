static int printf(const char *value)
{
    return value[0];
}

int main(int argc, char *argv[])
{
    printf(argv[1]);
    return argc;
}
