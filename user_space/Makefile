user_space.so: user_space.c
	gcc -Wall -fPIC -shared -o user_space.so user_space.c -ldl

test_p: test_performance.c
	gcc -Wall -o test_p test_performance.c

clean:
	rm *.so