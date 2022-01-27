# Symbolic

This is a Latin Square problem, with the addition of rules on the diagonal.

The solution can be computed by hand or using z3.

My head was aching, so I personally solved by hand, like a sudoku. 

It took some time but eventually I came up with this solution:

```
1 3 5 2 4
5 2 4 1 3
4 1 3 5 2
3 5 2 4 1
2 4 1 3 5
```

Note: This is just one of many solutions

## program

The input is then taken row by row and each row has to be separated by '-': 13524-52413-41352-35241-24135

Then the program yields the flag.
