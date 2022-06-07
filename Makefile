CC=g++
CFLAGS=@compile_flags.txt

main: main.cpp Url.cpp HttpClient.cpp
	$(CC) $^ $(CFLAGS) -o $@

clean:
	rm -f main test
