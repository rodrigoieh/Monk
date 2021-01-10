# Monk
It search in a PE for bytes that are equal in another PE

## Explaination
- increaser = How many bytes start to parse, example: [0:n] -> [0+n:n+n] -> [0+n+n:n+n+n] etc....
- increase = If after finished to parse the entire file restart again increasing the [increaser] (y/n)
- increase_v = How many bytes add to increaser after restarting
- times = How many times add bytes number to parse to [increase], example: if [increase_v] == 2 and [times] == 2 and [increase] == "y" and [increaser] = 8, the first parse will be
[0:increaser] and etc...., the second time will be [0:increaser+increase_v].

## Report
The report is divided in:

bytes | ascii | assembly [most of the times will be incorrect!]

The work to indentify if a match is unique and valuable for the analysis is work of the analyst.

P.S: The example report was the comparison of the same executable, see images [In this case the assemby is correct].

![](https://raw.githubusercontent.com/Finch4/Monk/main/hex.png?token=AMRB74AGCTDGDA7CXFGAW7K77HAUY)

![](https://raw.githubusercontent.com/Finch4/Monk/main/assembly.png?token=AMRB74BLJJQMLPHHAS4UZ7277HAVU)

![](https://raw.githubusercontent.com/Finch4/Monk/main/match.png?token=AMRB74CD5DNF3O4FV62Q4W277HAW4)
