package com.blog;
public class Employer { // Grouping by salary
    private String name;
    public String getName() {return name;
    }
    public String getCity() {return city;
    }
    public int getSalary() {
        return salary;
    }
    public Employer(String name, String city, int salary) {
        this.name = name;
        this.city = city;
        this.salary = salary;
    }
    private String city;
    private int salary;
}
