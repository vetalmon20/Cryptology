package ua.knu.hash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HavalTest {

    TestCase[] testCases = {

            // 128 Bit ----- ----- ----- ----- -----

            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Hello",
                    "4002D17F7B08E80048C27A6179552198"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Henlo",
                    "AFA14AC7F06184389FF842BF6D334608"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "0",
                    "7D440F12E37415D88F51ABAC417BA323"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "",
                    "C68F39913F901F3DDF44C707357A7D70"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Hello",
                    "7505FB2CD3E17FAF26C060D90FEAC153"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Henlo",
                    "F9F562AE6543C09C895C88D7BAA5CF57"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "0",
                    "050D72234AAE3BE69C26D4273DDC5FCD"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "",
                    "EE6BBF4D6A46A679B3A856C88538BB98"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Hello",
                    "B9FE471D6A1E2961925BA31820F8E73A"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Henlo",
                    "50749D05EF8FB0F9216DA0DCAA8C418C"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "0",
                    "A7BE7D591829D5BBE9F78499CFF8C9B9"
            ),
            new TestCase(
                    HavalSpec.HAVAL_128_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "",
                    "184B8482A0C050DCA54B59C7F05BF5DD"
            ),

            // 160 Bit ----- ----- ----- ----- -----

            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Hello",
                    "73C70CB6EF52DB1457443B038784584317137581"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Henlo",
                    "545C7B1ED0C328244BFCE31A748706E6B4A89DD6"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "0",
                    "509917832E854D235BBFA877E8CF8E79401FB0B7"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "",
                    "D353C3AE22A25401D257643836D7231A9A95F953"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Hello",
                    "6992A805B29CF46B78482A0D830A0DCF59A97DC7"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Henlo",
                    "46EF1DED3AD5EE52DDEAD7CA2E97D0B58543DF98"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "0",
                    "E6604245834A8F8A621A88BEE1AC7E2C44FAF81A"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "",
                    "1D33AAE1BE4146DBAACA0B6E70D7A11F10801525"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Hello",
                    "3B737F8F953FDF8AEEE2047EEE534D04E03E8513"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Henlo",
                    "F2AAD61BE503930966D3297C8BE5BDB587DD268B"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "0",
                    "3B8E06D08B8FF8AB762E3A6CF8597DCB75FB7DA1"
            ),
            new TestCase(
                    HavalSpec.HAVAL_160_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "",
                    "255158CFC1EED1A7BE7C55DDD64D9790415B933B"
            ),

            // 192 Bit ----- ----- ----- ----- -----

            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Hello",
                    "28AB2DE0468CCF4B87E6E84B79544FD8EF3C50743ED2E220"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Henlo",
                    "D8009CC46ACCB797E9866B28C8C377376FBFB8A044B112E3"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "0",
                    "45E2A105EB0EE229C5F1FF5A7E3F2C10FF8E5619E52AF9D5"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "",
                    "E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Hello",
                    "484AC833B792BC2937B2430EF95027E86C7ABC86BD1147E8"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Henlo",
                    "37BC41DC7F52CED09E6C58FEE9B4B456DEC98DB5FFE33F66"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "0",
                    "82607E9CF6ABC852089BFEAC4C9E170B1EB3A784A4FC5834"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "",
                    "4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Hello",
                    "4C3E872CF484706251B26F65B3C75DD0FE644C6A33A5CE9C"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Henlo",
                    "5D22CC5C064A6C80691BE653A2707F74129580793D99C08D"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "0",
                    "51B0D355E22D6C9B24684B0A0DA131E24C17E2F7B754CB63"
            ),
            new TestCase(
                    HavalSpec.HAVAL_192_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "",
                    "4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85"
            ),

            // 224 Bit ----- ----- ----- ----- -----

            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Hello",
                    "7C3883E323BFCA15EA58BB4A75EB42F772FB4998DBFFAE54F9142F05"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Henlo",
                    "DC84F392A98170CDBFDE22A645F0832CD9AD03A690B450C8122DA26D"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "0",
                    "F7F1599E3F234EA90A17B039630908BA1B11A7F0800714FF1A2D73F1"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "",
                    "C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Hello",
                    "29894B2A534F61DC77AC52C2A7A446246C6EF7728B84BB77A3DC6977"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Henlo",
                    "4602C8BD9EB9EA2C451C184ACD456F44E35D894B8561086BC232AD4F"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "0",
                    "C41C9107282518444FA8F7CD9443A683E8E6A9676A0AF9F014540CC3"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "",
                    "3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Hello",
                    "EAE0475BCD938756990FEC658C07E851D78B6A5A3C97DA3295A5DFA9"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Henlo",
                    "D4EAE880819A0144C0A0E57F20699C4B817A8631FF9B53856817D4E1"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "0",
                    "1F9C6DCF0D08AFD690CB197765CB31AC5F35DA42372FB7F916274BA2"
            ),
            new TestCase(
                    HavalSpec.HAVAL_224_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "",
                    "4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E"
            ),

            // 256 Bit ----- ----- ----- ----- -----

            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Hello",
                    "A6A9682BB0ED9C852369B327E02D9132ECDA1E76E0FEA87F81C3CF5920367C28"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "Henlo",
                    "14BFFE5F6F22D29BF8A834426F09B6BD5393DB42676A66A37B28DB8266A0B9B5"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "0",
                    "93DE8FDD3EB6F1938BB042204A62315DCAC8019306B39D8599166A66BB4FFAAD"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_3_ROUND,
                    "",
                    "4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Hello",
                    "EE43C751E7F77A021CE4EE5726A06C5C3BFF1702326F0E8D259D2055CA27D52E"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "Henlo",
                    "BC609BEBF13FB19AC09CC5A2712069C55E406B47E0584E4EC815B92096404417"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "0",
                    "CAD05C32B454189D8F7DE3EF483E1467468A59E2D3C331620099FFAC1B1C0F11"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_4_ROUND,
                    "",
                    "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Hello",
                    "3808FC5186E1DAB0FD35742305787A0017BDB41900BF43882404972788E36480"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Henlo",
                    "E948986F777D1B3CEB540115C6B2A70FCD56E9067DC7A075DAA7F550E2F957E3"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "0",
                    "8806ACAD71D6C4AAA61461943DE6A91B578699966F84774D821FF558FCA37A57"
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "",
                    "BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330"
            ),

            // Long text | 5 Round | 256 Bit   -----

            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "The quick brown fox jumps over the lazy dog",
                    "b89c551cdfe2e06dbd4cea2be1bc7d557416c58ebb4d07cbc94e49f710c55be4".toUpperCase()
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "The quick brown fox jumps over the lazy cog",
                    "60983bb8c8f49ad3bea29899b78cd741f4c96e911bbc272e5550a4f195a4077e".toUpperCase()
            ),
            new TestCase(
                    HavalSpec.HAVAL_256_BIT,
                    HavalSpec.HAVAL_5_ROUND,
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi egestas a risus eget pretium. Mauris blandit felis metus, a laoreet dui aliquet a. Cras rutrum id magna eu convallis. Etiam scelerisque nibh sit amet tempor varius. Etiam vel felis blandit, interdum mi ut, venenatis tortor. Maecenas facilisis, dui ut luctus ornare, est est gravida eros, in dictum magna augue id quam. Donec massa nisl, imperdiet nec nunc nec, faucibus mattis dui. Aliquam diam mauris, scelerisque non tortor non, gravida feugiat lorem. Integer vitae libero dignissim leo mollis consequat et at neque. Morbi arcu ante, viverra sed maximus tempus, tincidunt pellentesque sem.",
                    "e833e3a80d5790dcd4a6f9e512a1adf7a1b7cf37dbbdcc219ca1a476f7f46afa".toUpperCase()
            )
    };

    @Test
    void wrongArguments() {
        assertThrows(IllegalArgumentException.class, () -> new Haval(0, 0));

        assertThrows(IllegalArgumentException.class, () -> new Haval(0, 3));
        assertThrows(IllegalArgumentException.class, () -> new Haval(0, 4));
        assertThrows(IllegalArgumentException.class, () -> new Haval(0, 5));
        assertThrows(IllegalArgumentException.class, () -> new Haval(0, 6));

        assertThrows(IllegalArgumentException.class, () -> new Haval(16, 0));
        assertThrows(IllegalArgumentException.class, () -> new Haval(16, 6));
    }

    @Test
    void correctArguments() {
        assertDoesNotThrow(() -> new Haval(16, 3));
        assertDoesNotThrow(() -> new Haval(16, 4));
        assertDoesNotThrow(() -> new Haval(16, 5));

        assertDoesNotThrow(() -> new Haval(20, 3));
        assertDoesNotThrow(() -> new Haval(20, 4));
        assertDoesNotThrow(() -> new Haval(20, 5));

        assertDoesNotThrow(() -> new Haval(24, 3));
        assertDoesNotThrow(() -> new Haval(24, 4));
        assertDoesNotThrow(() -> new Haval(24, 5));

        assertDoesNotThrow(() -> new Haval(28, 3));
        assertDoesNotThrow(() -> new Haval(28, 4));
        assertDoesNotThrow(() -> new Haval(28, 5));

        assertDoesNotThrow(() -> new Haval(32, 3));
        assertDoesNotThrow(() -> new Haval(32, 4));
        assertDoesNotThrow(() -> new Haval(32, 5));
    }

    @Test
    void hash() {
        for (TestCase testCase : testCases) {
            Haval haval = new Haval(testCase.size, testCase.rounds);
            assertEquals(testCase.hash, haval.hash(testCase.string));
        }
    }

    @Test
    void defaultHash() {
        assertEquals(
                "A2C9B5D2BF3C0A81F9CF1986F261EAA8",
                new Haval().hash("default")
        );
    }

    private static class TestCase {
        private final int size;
        private final int rounds;
        private final String string;
        private final String hash;

        public TestCase(int size, int rounds, String string, String hash) {
            this.size = size;
            this.rounds = rounds;
            this.string = string;
            this.hash = hash;
        }
    }
}