package com.blog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

//Grouping by salary
public class MainUtil {
    public static void main(String[] args) {
        List<String> data = Arrays.asList("mike","mike","rahul","kajal","nikita");
        List<String> n = data.stream().filter(x->x.equals("mike")).collect(Collectors.toList());
        System.out.println(n.size());
    }
}
