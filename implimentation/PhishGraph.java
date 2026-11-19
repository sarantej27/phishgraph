/**
 * PhishGraph - Phishing Campaign Clustering Using Graph Learning (single-file version)
 * Research Project 05 (CTI). Infrastructure-based campaign clustering, NOT attacker attribution.
 *
 * Build : javac PhishGraph.java
 * Run   : java PhishGraph                  GUI; finds the CSV files itself and shows all results
 *         java PhishGraph a.csv b.csv      GUI on specific files
 *         java PhishGraph --cli            headless; prints results and saves results.txt
 * Needs : JDK 11+ (17 recommended)
 *
 * CSVs are searched in: Dataset, ../Dataset, dataset, data, ../data and the current folder.
 * CSV format: url,domain,ip,cert,timestamp,source,campaign   (campaign = ground-truth label, may be empty)
 */
import java.awt.*;
import java.io.*;
import java.io.File;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class PhishGraph {
    /** One observed phishing URL with its infrastructure attributes. Null/empty field = not observed. */
    static class Incident {
        public final int id;
        public final String url, domain, ip, cert, source;
        public final long timestamp;
        public final String label; // ground-truth campaign (may be null)

        public Incident(int id, String url, String domain, String ip, String cert,
                        long timestamp, String source, String label) {
            this.id = id; this.url = url; this.domain = domain; this.ip = ip;
            this.cert = cert; this.timestamp = timestamp; this.source = source; this.label = label;
        }

        public Incident withFields(String domain, String ip, String cert) {
            return new Incident(id, url, domain, ip, cert, timestamp, source, label);
        }
    }

    /** CSV loader, synthetic generator, and missing-observation simulator. */
    static class DataSource {

        /** CSV header: url,domain,ip,cert,timestamp,source,campaign  (campaign = ground-truth label). */
        public static List<Incident> loadCsv(File f) throws IOException {
            List<Incident> out = new ArrayList<>();
            try (BufferedReader br = Files.newBufferedReader(f.toPath())) {
                String line = br.readLine(); // header
                int id = 0;
                while ((line = br.readLine()) != null) {
                    if (line.isBlank()) continue;
                    String[] p = line.split(",", -1);
                    if (p.length < 7) continue;
                    long ts = 0;
                    try { ts = Long.parseLong(p[4].trim()); } catch (Exception ignored) {}
                    out.add(new Incident(id++, p[0].trim(), nz(p[1]), nz(p[2]), nz(p[3]), ts, p[5].trim(), nz(p[6])));
                }
            }
            return out;
        }

        public static void saveCsv(List<Incident> data, File f) throws IOException {
            try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(f.toPath()))) {
                pw.println("url,domain,ip,cert,timestamp,source,campaign");
                for (Incident i : data)
                    pw.println(String.join(",", s(i.url), s(i.domain), s(i.ip), s(i.cert),
                            String.valueOf(i.timestamp), s(i.source), s(i.label)));
            }
        }

        private static String nz(String s) { s = s.trim(); return s.isEmpty() ? null : s; }
        private static String s(String s) { return s == null ? "" : s; }

        /**
         * Synthetic data with a built-in trap: a fraction of incidents in every campaign sit on
         * a few SHARED hosting IPs/certs, which falsely link unrelated campaigns.
         */
        public static List<Incident> synthetic(int campaigns, int perCampaign, double sharedHostingRate, long seed) {
            Random r = new Random(seed);
            String[] sharedIps = {"104.21.0.1", "172.67.0.1", "185.199.0.1"};
            String[] sharedCerts = {"CN=cloudflare-shared", "CN=letsencrypt-wildcard"};
            List<Incident> out = new ArrayList<>();
            int id = 0;
            for (int c = 0; c < campaigns; c++) {
                String label = "CAMP-" + c;
                int nd = 2 + r.nextInt(3), ni = 1 + r.nextInt(2);
                String[] doms = new String[nd], ips = new String[ni];
                for (int i = 0; i < nd; i++) doms[i] = "secure-" + c + "-" + i + ".example-phish.top";
                for (int i = 0; i < ni; i++) ips[i] = "45." + (c % 250) + "." + i + "." + (1 + r.nextInt(250));
                String cert = "CN=camp" + c + "-ca-" + r.nextInt(3);
                long t0 = 1_700_000_000L + c * 86400L * 3;
                for (int k = 0; k < perCampaign; k++) {
                    String d = doms[r.nextInt(nd)];
                    boolean shared = r.nextDouble() < sharedHostingRate;
                    String ip = shared ? sharedIps[r.nextInt(sharedIps.length)] : ips[r.nextInt(ni)];
                    String ce = shared && r.nextBoolean() ? sharedCerts[r.nextInt(sharedCerts.length)] : cert;
                    out.add(new Incident(id, "http://" + d + "/login/" + Integer.toHexString(r.nextInt()),
                            d, ip, ce, t0 + r.nextInt(86400 * 5), "synthetic", label));
                    id++;
                }
            }
            Collections.shuffle(out, r);
            List<Incident> re = new ArrayList<>();
            for (int i = 0; i < out.size(); i++) { Incident o = out.get(i);
                re.add(new Incident(i, o.url, o.domain, o.ip, o.cert, o.timestamp, o.source, o.label)); }
            return re;
        }

        /** Robustness test: independently hide each of domain/ip/cert with probability 'rate'. */
        public static List<Incident> dropObservations(List<Incident> in, double rate, long seed) {
            Random r = new Random(seed);
            List<Incident> out = new ArrayList<>();
            for (Incident i : in)
                out.add(i.withFields(r.nextDouble() < rate ? null : i.domain,
                                     r.nextDouble() < rate ? null : i.ip,
                                     r.nextDouble() < rate ? null : i.cert));
            return out;
        }

        /** Looks for *.csv files in the usual dataset folders and the current folder. */
        public static List<File> findCsvFiles() {
            String[] dirs = {"Dataset", "../Dataset", "dataset", "data", "../data", "."};
            Map<String, File> found = new TreeMap<>();
            for (String d : dirs) {
                File[] fs = new File(d).listFiles((dir, name) -> name.toLowerCase().endsWith(".csv"));
                if (fs == null) continue;
                for (File f : fs) {
                    try { found.putIfAbsent(f.getCanonicalPath(), f); } catch (IOException ignored) {}
                }
            }
            return new ArrayList<>(found.values());
        }

        /** Temporal split (leakage-safe): earliest 'frac' of incidents vs the rest. */
        public static List<List<Incident>> temporalSplit(List<Incident> in, double frac) {
            List<Incident> s = new ArrayList<>(in);
            s.sort(Comparator.comparingLong(i -> i.timestamp));
            int k = (int) (s.size() * frac);
            return List.of(new ArrayList<>(s.subList(0, k)), new ArrayList<>(s.subList(k, s.size())));
        }
    }

    /** Clustering metrics: ARI, NMI, pairwise P/R/F1, B-cubed F1, purity. */
    static class Metrics {
        public double ari, nmi, pairP, pairR, pairF1, b3F1, purity;
        public int clusters;

        public static Metrics evaluate(int[] pred, String[] truth) {
            int n = pred.length;
            Map<String, Integer> tIdx = new HashMap<>();
            int[] t = new int[n];
            for (int i = 0; i < n; i++) t[i] = tIdx.computeIfAbsent(String.valueOf(truth[i]), k -> tIdx.size());

            Map<Integer, Integer> pSize = new HashMap<>(), tSize = new HashMap<>();
            Map<Long, Integer> joint = new HashMap<>();
            for (int i = 0; i < n; i++) {
                pSize.merge(pred[i], 1, Integer::sum);
                tSize.merge(t[i], 1, Integer::sum);
                joint.merge(((long) pred[i] << 32) | (t[i] & 0xffffffffL), 1, Integer::sum);
            }
            double sumJ = 0, sumP = 0, sumT = 0;
            for (int v : joint.values()) sumJ += c2(v);
            for (int v : pSize.values()) sumP += c2(v);
            for (int v : tSize.values()) sumT += c2(v);
            double total = c2(n);

            Metrics m = new Metrics();
            m.clusters = pSize.size();
            // pairwise
            m.pairP = sumP == 0 ? 0 : sumJ / sumP;
            m.pairR = sumT == 0 ? 0 : sumJ / sumT;
            m.pairF1 = (m.pairP + m.pairR) == 0 ? 0 : 2 * m.pairP * m.pairR / (m.pairP + m.pairR);
            // ARI
            double expected = sumP * sumT / total, max = 0.5 * (sumP + sumT);
            m.ari = (max - expected) == 0 ? 1.0 : (sumJ - expected) / (max - expected);
            // NMI (arithmetic mean)
            double hp = 0, ht = 0, mi = 0;
            for (int v : pSize.values()) { double p = (double) v / n; hp -= p * Math.log(p); }
            for (int v : tSize.values()) { double p = (double) v / n; ht -= p * Math.log(p); }
            for (Map.Entry<Long, Integer> e : joint.entrySet()) {
                int pi = (int) (e.getKey() >> 32), ti = (int) (long) e.getKey();
                double pij = (double) e.getValue() / n;
                mi += pij * Math.log(pij / (((double) pSize.get(pi) / n) * ((double) tSize.get(ti) / n)));
            }
            m.nmi = (hp + ht) == 0 ? 1.0 : 2 * mi / (hp + ht);
            // B-cubed + purity
            double bp = 0, br = 0;
            Map<Integer, Integer> maxInCluster = new HashMap<>();
            for (int i = 0; i < n; i++) {
                int same = joint.get(((long) pred[i] << 32) | (t[i] & 0xffffffffL));
                bp += (double) same / pSize.get(pred[i]);
                br += (double) same / tSize.get(t[i]);
                maxInCluster.merge(pred[i], same, Math::max);
            }
            bp /= n; br /= n;
            m.b3F1 = (bp + br) == 0 ? 0 : 2 * bp * br / (bp + br);
            double pur = 0; for (int v : maxInCluster.values()) pur += v;
            m.purity = pur / n;
            return m;
        }

        private static double c2(long k) { return k * (k - 1) / 2.0; }

        public String[] row(String name, long ms) {
            return new String[]{name, String.valueOf(clusters), f(ari), f(nmi), f(pairP), f(pairR), f(pairF1), f(b3F1), f(purity), ms + " ms"};
        }
        private static String f(double d) { return String.format("%.3f", d); }
        public static final String[] HEADER = {"Method", "#Clusters", "ARI", "NMI", "Pair P", "Pair R", "Pair F1", "B3 F1", "Purity", "Time"};
    }

    static interface Clusterer {
        String name();
        /** Returns a cluster id per incident (index-aligned with the input list). */
        int[] cluster(List<Incident> data);
    }

    static class Util {
        /** Observed infrastructure features of an incident (missing fields are skipped). */
        public static Set<String> features(Incident i) {
            Set<String> s = new HashSet<>();
            if (i.domain != null) s.add("d:" + i.domain);
            if (i.ip != null) s.add("i:" + i.ip);
            if (i.cert != null) s.add("c:" + i.cert);
            return s;
        }

        public static double jaccard(Set<String> a, Set<String> b) {
            if (a.isEmpty() && b.isEmpty()) return 0;
            int inter = 0;
            for (String x : a) if (b.contains(x)) inter++;
            return (double) inter / (a.size() + b.size() - inter);
        }

        static interface Dist { double d(int i, int j); }

        /** Generic DBSCAN; noise points become singleton clusters so metrics stay defined. */
        public static int[] dbscan(int n, Dist dist, double eps, int minPts) {
            int[] lab = new int[n];
            Arrays.fill(lab, -2); // -2 unvisited, -1 noise
            int cid = 0;
            for (int i = 0; i < n; i++) {
                if (lab[i] != -2) continue;
                List<Integer> nb = region(n, dist, i, eps);
                if (nb.size() < minPts) { lab[i] = -1; continue; }
                lab[i] = cid;
                Deque<Integer> q = new ArrayDeque<>(nb);
                while (!q.isEmpty()) {
                    int j = q.poll();
                    if (lab[j] == -1) lab[j] = cid;
                    if (lab[j] != -2) continue;
                    lab[j] = cid;
                    List<Integer> nb2 = region(n, dist, j, eps);
                    if (nb2.size() >= minPts) q.addAll(nb2);
                }
                cid++;
            }
            for (int i = 0; i < n; i++) if (lab[i] < 0) lab[i] = cid++;
            return lab;
        }

        private static List<Integer> region(int n, Dist dist, int i, double eps) {
            List<Integer> r = new ArrayList<>();
            for (int j = 0; j < n; j++) if (dist.d(i, j) <= eps) r.add(j);
            return r;
        }

        public static int[] relabel(int[] uf) {
            Map<Integer, Integer> m = new HashMap<>();
            int[] out = new int[uf.length];
            for (int i = 0; i < uf.length; i++) out[i] = m.computeIfAbsent(uf[i], k -> m.size());
            return out;
        }
    }

    /** Baseline 1: link incidents whose feature-set Jaccard >= threshold, take connected components. */
    static class JaccardComponents implements Clusterer {
        private final double threshold;
        public JaccardComponents(double threshold) { this.threshold = threshold; }
        public String name() { return "Jaccard + ConnComp (t=" + threshold + ")"; }

        public int[] cluster(List<Incident> data) {
            int n = data.size();
            List<Set<String>> f = new ArrayList<>();
            for (Incident i : data) f.add(Util.features(i));
            int[] uf = new int[n];
            for (int i = 0; i < n; i++) uf[i] = i;
            for (int i = 0; i < n; i++)
                for (int j = i + 1; j < n; j++)
                    if (Util.jaccard(f.get(i), f.get(j)) >= threshold) union(uf, i, j);
            int[] root = new int[n];
            for (int i = 0; i < n; i++) root[i] = find(uf, i);
            return Util.relabel(root);
        }

        static int find(int[] p, int x) { while (p[x] != x) { p[x] = p[p[x]]; x = p[x]; } return x; }
        static void union(int[] p, int a, int b) { p[find(p, a)] = find(p, b); }
    }

    /**
     * Hub-aware baseline: IDF-weighted Jaccard. Infrastructure shared by many incidents
     * (shared hosting, CDN IPs, wildcard certs) gets low weight, so it cannot chain unrelated campaigns.
     */
    static class IdfJaccardComponents implements Clusterer {
        private final double threshold;
        public IdfJaccardComponents(double threshold) { this.threshold = threshold; }
        public String name() { return "IDF-Jaccard + ConnComp (t=" + threshold + ")"; }

        public int[] cluster(List<Incident> data) {
            int n = data.size();
            List<Set<String>> f = new ArrayList<>();
            Map<String, Integer> df = new HashMap<>();
            for (Incident i : data) { Set<String> s = Util.features(i); f.add(s); for (String x : s) df.merge(x, 1, Integer::sum); }
            Map<String, Double> w = new HashMap<>();
            for (Map.Entry<String, Integer> e : df.entrySet()) w.put(e.getKey(), Math.log((double) n / e.getValue()));
            int[] uf = new int[n];
            for (int i = 0; i < n; i++) uf[i] = i;
            for (int i = 0; i < n; i++)
                for (int j = i + 1; j < n; j++) {
                    double inter = 0, uni = 0;
                    Set<String> a = f.get(i), b = f.get(j);
                    for (String x : a) { double wx = w.get(x); uni += wx; if (b.contains(x)) inter += wx; }
                    for (String x : b) if (!a.contains(x)) uni += w.get(x);
                    if (uni > 0 && inter / uni >= threshold) JaccardComponents.union(uf, i, j);
                }
            int[] root = new int[n];
            for (int i = 0; i < n; i++) root[i] = JaccardComponents.find(uf, i);
            return Util.relabel(root);
        }
    }

    /** Baseline 2: DBSCAN over engineered features using Jaccard distance. */
    static class DbscanJaccard implements Clusterer {
        private final double eps; private final int minPts;
        public DbscanJaccard(double eps, int minPts) { this.eps = eps; this.minPts = minPts; }
        public String name() { return "DBSCAN-Jaccard (eps=" + eps + ", minPts=" + minPts + ")"; }

        public int[] cluster(List<Incident> data) {
            List<Set<String>> f = new ArrayList<>();
            for (Incident i : data) f.add(Util.features(i));
            return Util.dbscan(data.size(), (a, b) -> 1.0 - Util.jaccard(f.get(a), f.get(b)), eps, minPts);
        }
    }

    /**
     * Heterogeneous graph: URL nodes connect to the DOMAIN / IP / CERT nodes they were observed with.
     * Every edge carries the incident's timestamp + source (provenance) in edgeMeta / edgeSource.
     */
    static class InfraGraph {
        public final List<String> nodeName = new ArrayList<>();
        public final Map<String, Integer> index = new HashMap<>();
        public final List<List<Integer>> adjList = new ArrayList<>();
        public int[] urlNode;           // incident index -> node id
        public int[][] adj;             // sorted neighbour arrays
        public final Map<Long, long[]> edgeMeta = new HashMap<>(); // key(u,v) -> {timestamp}
        public final Map<Long, String> edgeSource = new HashMap<>();

        public static InfraGraph build(List<Incident> data) {
            InfraGraph g = new InfraGraph();
            g.urlNode = new int[data.size()];
            for (int k = 0; k < data.size(); k++) {
                Incident i = data.get(k);
                int u = g.node("u:" + i.id);
                g.urlNode[k] = u;
                g.link(u, i.domain == null ? null : "d:" + i.domain, i);
                g.link(u, i.ip == null ? null : "i:" + i.ip, i);
                g.link(u, i.cert == null ? null : "c:" + i.cert, i);
            }
            g.adj = new int[g.adjList.size()][];
            for (int v = 0; v < g.adj.length; v++)
                g.adj[v] = g.adjList.get(v).stream().distinct().mapToInt(Integer::intValue).sorted().toArray();
            return g;
        }

        private int node(String name) {
            Integer id = index.get(name);
            if (id != null) return id;
            index.put(name, nodeName.size()); nodeName.add(name); adjList.add(new ArrayList<>());
            return nodeName.size() - 1;
        }

        private void link(int u, String entity, Incident i) {
            if (entity == null) return;
            int v = node(entity);
            adjList.get(u).add(v); adjList.get(v).add(u);
            long key = ((long) Math.min(u, v) << 32) | Math.max(u, v);
            edgeMeta.put(key, new long[]{i.timestamp});
            edgeSource.put(key, i.source);
        }

        public int size() { return nodeName.size(); }
        public boolean hasEdge(int a, int b) { return Arrays.binarySearch(adj[a], b) >= 0; }
    }

    /**
     * Baseline 3: Node2Vec (biased 2nd-order random walks + skip-gram with negative sampling),
     * followed by DBSCAN on cosine distance of URL-node embeddings.
     */
    static class Node2VecClusterer implements Clusterer {
        private final int dim, walks, walkLen, window, neg, epochs;
        private final double p, q, eps; private final int minPts; private final long seed;

        public Node2VecClusterer(int dim, int walks, int walkLen, double p, double q, double eps, int minPts, long seed) {
            this.dim = dim; this.walks = walks; this.walkLen = walkLen; this.p = p; this.q = q;
            this.eps = eps; this.minPts = minPts; this.seed = seed; this.window = 5; this.neg = 5; this.epochs = 3;
        }
        public String name() { return "Node2Vec + DBSCAN (d=" + dim + ", p=" + p + ", q=" + q + ")"; }

        public int[] cluster(List<Incident> data) {
            InfraGraph g = InfraGraph.build(data);
            float[][] emb = embed(g);
            int n = data.size();
            float[][] x = new float[n][];
            for (int k = 0; k < n; k++) x[k] = normalize(emb[g.urlNode[k]]);
            return Util.dbscan(n, (a, b) -> 1.0 - dot(x[a], x[b]), eps, minPts);
        }

        public float[][] embed(InfraGraph g) {
            Random r = new Random(seed);
            int N = g.size();
            List<int[]> corpus = new ArrayList<>();
            Integer[] order = new Integer[N];
            for (int i = 0; i < N; i++) order[i] = i;
            for (int w = 0; w < walks; w++) {
                Collections.shuffle(Arrays.asList(order), r);
                for (int s : order) if (g.adj[s].length > 0) corpus.add(walk(g, s, r));
            }
            float[][] in = new float[N][dim], out = new float[N][dim];
            for (float[] row : in) for (int d = 0; d < dim; d++) row[d] = (r.nextFloat() - 0.5f) / dim;
            long totalSteps = (long) epochs * corpus.size(), step = 0;
            for (int ep = 0; ep < epochs; ep++) {
                Collections.shuffle(corpus, r);
                for (int[] wk : corpus) {
                    float lr = (float) Math.max(0.0001, 0.025 * (1.0 - (double) step++ / totalSteps));
                    for (int i = 0; i < wk.length; i++) {
                        int lo = Math.max(0, i - window), hi = Math.min(wk.length - 1, i + window);
                        for (int j = lo; j <= hi; j++) {
                            if (j == i) continue;
                            train(in[wk[i]], out[wk[j]], 1f, lr);
                            for (int k = 0; k < neg; k++) {
                                int ng = r.nextInt(N);
                                if (ng != wk[j]) train(in[wk[i]], out[ng], 0f, lr);
                            }
                        }
                    }
                }
            }
            return in;
        }

        private void train(float[] a, float[] b, float label, float lr) {
            float s = dot(a, b);
            float g = (label - 1f / (1f + (float) Math.exp(-Math.max(-8, Math.min(8, s))))) * lr;
            for (int d = 0; d < dim; d++) { float ad = a[d]; a[d] += g * b[d]; b[d] += g * ad; }
        }

        private int[] walk(InfraGraph g, int start, Random r) {
            int[] w = new int[walkLen];
            w[0] = start;
            int len = 1;
            while (len < walkLen) {
                int cur = w[len - 1];
                int[] nb = g.adj[cur];
                if (nb.length == 0) break;
                if (len == 1) { w[len++] = nb[r.nextInt(nb.length)]; continue; }
                int prev = w[len - 2];
                double[] wt = new double[nb.length];
                double sum = 0;
                for (int i = 0; i < nb.length; i++) {
                    wt[i] = nb[i] == prev ? 1.0 / p : (g.hasEdge(prev, nb[i]) ? 1.0 : 1.0 / q);
                    sum += wt[i];
                }
                double x = r.nextDouble() * sum; int pick = nb.length - 1;
                for (int i = 0; i < nb.length; i++) { x -= wt[i]; if (x <= 0) { pick = i; break; } }
                w[len++] = nb[pick];
            }
            return Arrays.copyOf(w, len);
        }

        private static float dot(float[] a, float[] b) { float s = 0; for (int i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
        private static float[] normalize(float[] v) {
            float n = (float) Math.sqrt(dot(v, v)) + 1e-9f; float[] o = new float[v.length];
            for (int i = 0; i < v.length; i++) o[i] = v[i] / n; return o;
        }
    }

    static class Experiment {
        public static List<Clusterer> methods() {
            return List.of(
                new JaccardComponents(0.60),
                new IdfJaccardComponents(0.60),
                new DbscanJaccard(0.30, 2),
                new Node2VecClusterer(32, 10, 40, 1.0, 0.5, 0.10, 3, 42L)
            );
        }

        public static class Result { public final String name; public final Metrics m; public final long ms;
            Result(String n, Metrics m, long ms) { name = n; this.m = m; this.ms = ms; } }

        public static List<Result> runAll(List<Incident> data) {
            String[] truth = data.stream().map(i -> i.label == null ? "?" : i.label).toArray(String[]::new);
            List<Result> res = new ArrayList<>();
            for (Clusterer c : methods()) {
                long t = System.currentTimeMillis();
                int[] pred = c.cluster(data);
                res.add(new Result(c.name(), Metrics.evaluate(pred, truth), System.currentTimeMillis() - t));
            }
            return res;
        }

        /** Robustness: hide observations at increasing rates; returns rows {rate, method, ARI, B3F1}. */
        public static List<String[]> robustness(List<Incident> data, double[] rates) {
            List<String[]> rows = new ArrayList<>();
            for (double rate : rates) {
                List<Incident> d = DataSource.dropObservations(data, rate, 7L);
                for (Result r : runAll(d))
                    rows.add(new String[]{String.format("%.0f%%", rate * 100), r.name,
                            String.format("%.3f", r.m.ari), String.format("%.3f", r.m.b3F1)});
            }
            return rows;
        }

        static int campaignCount(List<Incident> d) {
            Set<String> s = new HashSet<>();
            for (Incident i : d) if (i.label != null) s.add(i.label);
            return s.size();
        }

        /** Loads every CSV (file name -> incidents); unreadable or empty files are skipped with a warning. */
        public static Map<String, List<Incident>> loadAll(List<File> files) {
            Map<String, List<Incident>> m = new LinkedHashMap<>();
            for (File f : files) {
                try {
                    List<Incident> d = DataSource.loadCsv(f);
                    if (d.isEmpty()) System.err.println("Skipped (no valid rows): " + f);
                    else m.put(f.getName(), d);
                } catch (Exception ex) { System.err.println("Skipped " + f + ": " + ex); }
            }
            return m;
        }

        /** Runs all methods (and the robustness sweep) on every dataset and returns a text report. */
        public static String report(Map<String, List<Incident>> sets) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, List<Incident>> e : sets.entrySet()) {
                List<Incident> d = e.getValue();
                sb.append("=== ").append(e.getKey()).append("  (").append(d.size()).append(" incidents, ")
                  .append(campaignCount(d)).append(" true campaigns) ===\n");
                sb.append(String.join("\t", Metrics.HEADER)).append('\n');
                for (Result r : runAll(d)) sb.append(String.join("\t", r.m.row(r.name, r.ms))).append('\n');
                sb.append("\nRobustness (missing observations)\nMissing\tMethod\tARI\tB3 F1\n");
                for (String[] row : robustness(d, new double[]{0.1, 0.3, 0.5})) sb.append(String.join("\t", row)).append('\n');
                sb.append('\n');
            }
            return sb.toString();
        }

        /** Headless run: java PhishGraph --cli [file1.csv file2.csv ...]  (no files = auto-find CSVs). */
        public static void main(String[] a) {
            List<File> files = new ArrayList<>();
            for (String s : a) if (s.toLowerCase().endsWith(".csv")) files.add(new File(s));
            if (files.isEmpty()) files = DataSource.findCsvFiles();
            Map<String, List<Incident>> sets = loadAll(files);
            if (sets.isEmpty()) {
                System.out.println("No CSV files found - using built-in synthetic data.");
                sets.put("synthetic (built-in)", DataSource.synthetic(12, 40, 0.25, 1L));
            }
            String rep = report(sets);
            System.out.println(rep);
            try { Files.writeString(Paths.get("results.txt"), rep); System.out.println("Saved results.txt"); }
            catch (IOException ex) { System.err.println("Could not save results.txt: " + ex); }
        }
    }

    /** Swing front end: finds the CSV files itself, runs everything and fills the tables. */
    static class App extends JFrame {
        private Map<String, List<Incident>> sets = new LinkedHashMap<>();
        private final List<File> given;
        private final JLabel status = new JLabel("Starting...");
        private final DefaultTableModel resultModel = new DefaultTableModel(withFirst("Dataset", Metrics.HEADER), 0);
        private final DefaultTableModel robustModel = new DefaultTableModel(new String[]{"Dataset", "Missing", "Method", "ARI", "B3 F1"}, 0);
        private final JTextArea log = new JTextArea(6, 60);

        public App(List<File> given) {
            super("PhishGraph - Phishing Campaign Clustering (infrastructure-based, not attacker attribution)");
            this.given = given;
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            JButton rescan = new JButton("Rescan folders & run all");
            JButton load = new JButton("Load other CSV...");
            JButton run = new JButton("Run all methods");
            JButton rob = new JButton("Robustness sweep");
            JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
            for (JButton b : new JButton[]{rescan, load, run, rob}) top.add(b);

            JTabbedPane tabs = new JTabbedPane();
            tabs.add("Results", new JScrollPane(new JTable(resultModel)));
            tabs.add("Robustness", new JScrollPane(new JTable(robustModel)));
            log.setEditable(false);
            JPanel south = new JPanel(new BorderLayout());
            south.add(new JScrollPane(log), BorderLayout.CENTER);
            south.add(status, BorderLayout.SOUTH);
            add(top, BorderLayout.NORTH); add(tabs, BorderLayout.CENTER); add(south, BorderLayout.SOUTH);

            rescan.addActionListener(e -> autoRun());
            load.addActionListener(e -> {
                JFileChooser fc = new JFileChooser(new File("."));
                if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
                File f = fc.getSelectedFile();
                work(() -> {
                    try {
                        List<Incident> d = DataSource.loadCsv(f);
                        if (d.isEmpty()) { info("No valid rows in " + f.getName()); return; }
                        sets.put(f.getName(), d);
                        info("Loaded " + d.size() + " incidents from " + f.getName());
                        runResults(); runRobustness();
                    } catch (Exception ex) { error(ex); }
                });
            });
            run.addActionListener(e -> work(this::runResults));
            rob.addActionListener(e -> work(this::runRobustness));
            pack(); setSize(1100, 650); setLocationRelativeTo(null);
        }

        /** Finds the CSV files (or uses the ones given on the command line) and runs everything. */
        void autoRun() {
            work(() -> {
                List<File> files = given.isEmpty() ? DataSource.findCsvFiles() : given;
                Map<String, List<Incident>> m = Experiment.loadAll(files);
                if (m.isEmpty()) {
                    m.put("synthetic (no CSV found)", DataSource.synthetic(12, 40, 0.25, 1L));
                    info("No CSV files found - using built-in synthetic data.");
                } else info("Found " + m.size() + " dataset(s): " + m.keySet());
                sets = m;
                runResults();
                runRobustness();
            });
        }

        private void runResults() {
            Map<String, List<Incident>> snap = new LinkedHashMap<>(sets);
            if (snap.isEmpty()) { info("No data loaded."); return; }
            setStatus("Running all methods...");
            List<String[]> rows = new ArrayList<>();
            for (Map.Entry<String, List<Incident>> e : snap.entrySet())
                for (Experiment.Result r : Experiment.runAll(e.getValue()))
                    rows.add(withFirst(e.getKey(), r.m.row(r.name, r.ms)));
            SwingUtilities.invokeLater(() -> {
                resultModel.setRowCount(0);
                rows.forEach(resultModel::addRow);
                info("Results ready for " + snap.size() + " dataset(s). Clusters = shared infrastructure, not proof of one attacker.");
            });
        }

        private void runRobustness() {
            Map<String, List<Incident>> snap = new LinkedHashMap<>(sets);
            if (snap.isEmpty()) return;
            setStatus("Running robustness sweep...");
            List<String[]> rows = new ArrayList<>();
            for (Map.Entry<String, List<Incident>> e : snap.entrySet())
                for (String[] r : Experiment.robustness(e.getValue(), new double[]{0.0, 0.1, 0.2, 0.3, 0.5}))
                    rows.add(withFirst(e.getKey(), r));
            SwingUtilities.invokeLater(() -> {
                robustModel.setRowCount(0);
                rows.forEach(robustModel::addRow);
                info("Robustness sweep done.");
            });
        }

        private static String[] withFirst(String first, String[] rest) {
            String[] out = new String[rest.length + 1];
            out[0] = first;
            System.arraycopy(rest, 0, out, 1, rest.length);
            return out;
        }

        private void work(Runnable r) {
            new Thread(() -> {
                try { r.run(); } catch (Exception ex) { error(ex); }
            }).start();
        }
        private void setStatus(String s) { SwingUtilities.invokeLater(() -> status.setText(s)); }
        private void info(String s) { SwingUtilities.invokeLater(() -> { status.setText(s); log.append(s + "\n"); }); }
        private void error(Exception ex) {
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, ex.toString(), "Error", JOptionPane.ERROR_MESSAGE));
        }
    }

    public static void main(String[] args) {
        boolean cli = false;
        List<File> given = new ArrayList<>();
        for (String s : args) {
            if (s.equals("--cli")) cli = true;
            else if (s.toLowerCase().endsWith(".csv")) given.add(new File(s));
        }
        if (cli) { Experiment.main(args); return; }
        SwingUtilities.invokeLater(() -> {
            App app = new App(given);
            app.setVisible(true);
            app.autoRun();
        });
    }
}