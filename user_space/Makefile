user_space.so: user_space.c
	gcc -Wall -fPIC -shared -o user_space.so user_space.c -ldl

test: test.c
	gcc  -g -o test test.c

test1: test1.c
	gcc  -g -o test1 test1.c

test2: test2.c
	gcc  -g -o test2 test2.c

test3: test3.c
	gcc  -g -o test3 test3.c

test4: test4.c
	gcc  -g -o test4 test4.c

test5: test5.c
	gcc  -g -o test5 test5.c

test_p: test_performance.c
	gcc -g -o test_p test_performance.c

clean:
	rm *.so test test1 test2 test3 test4 test5 test_p
