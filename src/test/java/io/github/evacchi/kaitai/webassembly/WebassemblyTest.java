package io.github.evacchi.kaitai.webassembly;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class WebassemblyTest {

    static class ArgProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) throws Exception {
            return Files.list(Path.of("src/test/resources")).map(Arguments::of);
        }
    }

    @ParameterizedTest
    @ArgumentsSource(ArgProvider.class)
    public void probeTest(Path p) throws IOException {
        Webassembly webassembly = Webassembly.fromFile(p.toString());
    }

}