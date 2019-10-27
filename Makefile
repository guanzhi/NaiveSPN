all:
	cc -Wall test.c naivespn.c -o test

clean:
	rm -fr test
