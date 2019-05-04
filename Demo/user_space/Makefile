user_space.so: user_space.c
	gcc -Wall -fPIC -shared -o user_space.so user_space.c -ldl

test: test.c
	gcc  -g -o test test.c


test_p: test_performance.c
	gcc -g -o test_p test_performance.c

clean:
	rm *.so
