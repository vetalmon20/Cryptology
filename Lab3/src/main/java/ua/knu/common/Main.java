package ua.knu.common;

import ua.knu.hash.Haval;
import ua.knu.hash.HavalSpec;

public class Main {
    public static void main(String[] args) {
        Haval haval = new Haval(HavalSpec.HAVAL_256_BIT, HavalSpec.HAVAL_5_ROUND);
        String[] strings = {
                "Hello",
                "Henlo",
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
                        "Integer et eros ultricies enim convallis mattis."
        };

        for (String string : strings) {
            System.out.println(string + " : " + haval.hash(string));
        }
    }
}
