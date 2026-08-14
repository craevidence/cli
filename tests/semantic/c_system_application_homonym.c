static int system(const char *value)
{
    return value[0];
}

int main(int argc, char *argv[])
{
    system(argv[1]);
    return argc;
}
