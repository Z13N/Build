package releasedata;

/** Minimal replacement for java.util.zip.ZipEntry used by DataUtils. */
public class ArchiveEntry {
    private final String name;
    private final boolean directory;

    public ArchiveEntry(String name, boolean directory) {
        this.name = name;
        this.directory = directory;
    }

    public String getName() { return name; }

    public boolean isDirectory() { return directory; }
}
