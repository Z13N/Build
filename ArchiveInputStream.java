package releasedata;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.tukaani.xz.XZInputStream;

/**
 * Drop-in replacement for ZipInputStream. Auto-detects the format by magic
 * bytes: .zip, .tar.xz (.txz) and .tar.gz (.tgz). Detection is lazy (first
 * getNextEntry call) so the constructor never throws.
 */
public class ArchiveInputStream extends InputStream {
    private static final int BLOCK = 512;

    private final InputStream source;
    private PushbackInputStream pb;
    private ZipInputStream zip;      // zip mode
    private InputStream tarIn;       // tar mode (decompressed stream)
    private boolean inited;
    private long remaining;          // bytes left in current tar entry
    private long padding;            // padding after current tar entry
    private boolean tarEof;

    public ArchiveInputStream(InputStream in) {
        this.source = in;
    }

    /** True if the stream starts with a zip, xz or gzip signature. Consumes up to 6 bytes. */
    public static boolean isArchive(InputStream in) throws IOException {
        int b0 = in.read();
        int b1 = in.read();
        if (b0 == 0x50 && b1 == 0x4B) return true;            // PK
        if (b0 == 0x1F && b1 == 0x8B) return true;            // gzip
        if (b0 == 0xFD && b1 == 0x37) {                       // xz: FD 37 7A 58 5A 00
            return in.read() == 0x7A && in.read() == 0x58
                    && in.read() == 0x5A && in.read() == 0x00;
        }
        return false;
    }

    private void init() throws IOException {
        if (inited) return;
        inited = true;
        pb = new PushbackInputStream(source, 8);
        byte[] m = new byte[6];
        int n = 0;
        while (n < m.length) {
            int r = pb.read(m, n, m.length - n);
            if (r < 0) break;
            n += r;
        }
        if (n > 0) pb.unread(m, 0, n);
        if (n >= 2 && m[0] == 'P' && m[1] == 'K') {
            zip = new ZipInputStream(pb);
        } else if (n >= 6 && (m[0] & 0xFF) == 0xFD && m[1] == 0x37 && m[2] == 0x7A
                && m[3] == 0x58 && m[4] == 0x5A && m[5] == 0x00) {
            tarIn = new XZInputStream(pb);
        } else if (n >= 2 && (m[0] & 0xFF) == 0x1F && (m[1] & 0xFF) == 0x8B) {
            tarIn = new GZIPInputStream(pb);
        } else {
            throw new IOException("Unsupported archive format (need zip, tar.xz or tar.gz)");
        }
    }

    public ArchiveEntry getNextEntry() throws IOException {
        init();
        if (zip != null) {
            ZipEntry ze;
            while ((ze = zip.getNextEntry()) != null) {
                String name = safeName(ze.getName());
                if (name != null) return new ArchiveEntry(name, ze.isDirectory());
            }
            return null;
        }
        return nextTarEntry();
    }

    public void closeEntry() throws IOException {
        if (zip != null) zip.closeEntry();
        else if (tarIn != null) skipCurrentTarEntry();
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int r = read(one, 0, 1);
        return r < 0 ? -1 : (one[0] & 0xFF);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (zip != null) return zip.read(b, off, len);
        if (tarIn == null || remaining <= 0) return -1;
        if (len == 0) return 0;
        int r = tarIn.read(b, off, (int) Math.min(len, remaining));
        if (r < 0) throw new IOException("Truncated tar archive");
        remaining -= r;
        return r;
    }

    @Override
    public void close() throws IOException {
        if (zip != null) zip.close();
        else if (tarIn != null) tarIn.close();
        else source.close();
    }

    // ------------------------------------------------------------ tar

    private ArchiveEntry nextTarEntry() throws IOException {
        if (tarEof) return null;
        skipCurrentTarEntry();
        String longName = null;
        long paxSize = -1;
        byte[] h = new byte[BLOCK];
        while (true) {
            if (!readFully(tarIn, h, BLOCK)) { tarEof = true; return null; }
            if (isZeroBlock(h)) { tarEof = true; return null; }

            long size = parseNumber(h, 124, 12);
            char type = (char) (h[156] & 0xFF);
            String name = cstr(h, 0, 100);
            if (h[257] == 'u' && h[258] == 's' && h[259] == 't' && h[260] == 'a' && h[261] == 'r') {
                String prefix = cstr(h, 345, 155);
                if (prefix.length() > 0) name = prefix + "/" + name;
            }

            if (type == 'L') {                      // GNU long name
                longName = trimNul(new String(readData(size), "UTF-8"));
                skipBytes(pad(size));
                continue;
            }
            if (type == 'x') {                      // pax extended header (next entry)
                String[] pax = parsePax(readData(size));
                if (pax[0] != null) longName = pax[0];
                if (pax[1] != null) paxSize = Long.parseLong(pax[1]);
                skipBytes(pad(size));
                continue;
            }
            if (type == 'g') {                      // pax global header: ignore
                skipBytes(size + pad(size));
                continue;
            }

            if (longName != null) { name = longName; longName = null; }
            if (paxSize >= 0) { size = paxSize; paxSize = -1; }

            boolean dir = type == '5' || (type == '0' || type == 0 ? name.endsWith("/") : false);
            boolean regular = type == '0' || type == 0 || type == '7';
            String safe = safeName(name);

            if ((!regular && !dir) || safe == null) {   // links, devices, unsafe paths
                skipBytes(size + pad(size));
                continue;
            }
            remaining = dir ? 0 : size;
            padding = dir ? (size + pad(size)) : pad(size);
            return new ArchiveEntry(safe, dir);
        }
    }

    private void skipCurrentTarEntry() throws IOException {
        if (remaining > 0) { skipBytes(remaining); remaining = 0; }
        if (padding > 0) { skipBytes(padding); padding = 0; }
    }

    private static long pad(long size) { return (BLOCK - (size % BLOCK)) % BLOCK; }

    private void skipBytes(long n) throws IOException {
        byte[] buf = new byte[8192];
        while (n > 0) {
            int r = tarIn.read(buf, 0, (int) Math.min(buf.length, n));
            if (r < 0) throw new IOException("Truncated tar archive");
            n -= r;
        }
    }

    private byte[] readData(long size) throws IOException {
        if (size > 1 << 20) throw new IOException("Tar metadata too large");
        byte[] d = new byte[(int) size];
        if (!readFully(tarIn, d, d.length)) throw new IOException("Truncated tar archive");
        return d;
    }

    private static boolean readFully(InputStream in, byte[] b, int len) throws IOException {
        int n = 0;
        while (n < len) {
            int r = in.read(b, n, len - n);
            if (r < 0) return n != 0 ? failTruncated() : false;
            n += r;
        }
        return true;
    }

    private static boolean failTruncated() throws IOException {
        throw new IOException("Truncated tar archive");
    }

    private static boolean isZeroBlock(byte[] h) {
        for (int i = 0; i < h.length; i++) if (h[i] != 0) return false;
        return true;
    }

    private static long parseNumber(byte[] h, int off, int len) {
        if ((h[off] & 0x80) != 0) {                 // base-256 (GNU, huge files)
            long v = h[off] & 0x7F;
            for (int i = 1; i < len; i++) v = (v << 8) | (h[off + i] & 0xFF);
            return v;
        }
        long v = 0;
        for (int i = off; i < off + len; i++) {
            int c = h[i] & 0xFF;
            if (c == 0 || c == ' ') { if (v == 0 && c == ' ') continue; break; }
            if (c < '0' || c > '7') break;
            v = (v << 3) + (c - '0');
        }
        return v;
    }

    private static String cstr(byte[] h, int off, int max) {
        int end = off;
        while (end < off + max && h[end] != 0) end++;
        try { return new String(h, off, end - off, "UTF-8"); }
        catch (java.io.UnsupportedEncodingException e) { return new String(h, off, end - off); }
    }

    private static String trimNul(String s) {
        int i = s.indexOf('\0');
        return i >= 0 ? s.substring(0, i) : s;
    }

    /** returns {path, size} from a pax header record block. */
    private static String[] parsePax(byte[] d) throws IOException {
        String[] res = new String[2];
        int pos = 0;
        while (pos < d.length) {
            int sp = pos;
            while (sp < d.length && d[sp] != ' ') sp++;
            int len = Integer.parseInt(new String(d, pos, sp - pos, "UTF-8"));
            if (len <= 0 || pos + len > d.length) break;
            String rec = new String(d, sp + 1, pos + len - sp - 2, "UTF-8"); // strip trailing \n
            int eq = rec.indexOf('=');
            if (eq > 0) {
                String k = rec.substring(0, eq), v = rec.substring(eq + 1);
                if (k.equals("path")) res[0] = v;
                else if (k.equals("size")) res[1] = v;
            }
            pos += len;
        }
        return res;
    }

    /** Normalizes an entry name; returns null if it would escape the target dir. */
    static String safeName(String name) {
        if (name == null) return null;
        name = name.replace('\\', '/');
        while (name.startsWith("./")) name = name.substring(2);
        if (name.length() == 0 || name.equals(".")) return null;
        for (String part : name.split("/")) {
            if (part.equals("..")) return null;
        }
        return name;
    }
}
