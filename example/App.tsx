import React, {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {
  ActivityIndicator,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  useColorScheme,
  View,
} from 'react-native';
import {SafeAreaProvider, SafeAreaView} from 'react-native-safe-area-context';
import ReactNativeBlobUtil from 'react-native-blob-util';

import {registeredGroups, run, TestResult, totalTests} from './src/harness';
import './src/tests';

type Filter = 'all' | 'failed';

export const RESULTS_FILE = 'sodium-test-results.json';

/**
 * Which group to run automatically on launch. undefined runs everything except
 * the manual groups (benchmarks). Set to a group name to drive that group from
 * a terminal without tapping its chip.
 */
const RUN_ON_LAUNCH: string | undefined = undefined;

export default function App() {
  const isDark = useColorScheme() === 'dark';
  const theme = isDark ? dark : light;

  // Read at render time rather than module scope so a Fast Refresh re-import
  // is reflected instead of showing a stale count.
  const groups = registeredGroups();
  const total = totalTests();

  const [results, setResults] = useState<TestResult[]>([]);
  const [running, setRunning] = useState(false);
  const [group, setGroup] = useState<string | undefined>(undefined);
  const [filter, setFilter] = useState<Filter>('all');
  const [elapsed, setElapsed] = useState(0);
  const collected = useRef<TestResult[]>([]);

  const start = useCallback(
    async (only?: string) => {
      if (running) return;
      collected.current = [];
      setResults([]);
      setGroup(only);
      setElapsed(0);
      setRunning(true);
      const began = Date.now();
      try {
        await run(result => {
          collected.current = [...collected.current, result];
          setResults(collected.current);
          console.log(
            `SODIUM_TEST ${result.status.toUpperCase()} | ${result.group} | ${
              result.name
            }${result.error ? ` | ${result.error}` : ''}`,
          );
        }, only);
      } finally {
        const all = collected.current;
        setElapsed(Date.now() - began);
        setRunning(false);
        console.log(
          `SODIUM_TEST_SUMMARY ${JSON.stringify({
            platform: Platform.OS,
            version: Platform.Version,
            total: all.length,
            passed: all.filter(r => r.status === 'pass').length,
            failed: all.filter(r => r.status === 'fail').length,
            skipped: all.filter(r => r.status === 'skip').length,
            ms: Date.now() - began,
          })}`,
        );
        console.log('SODIUM_TEST_DONE');

        // Also written to disk: console output is not reliably reachable from
        // the host on iOS, and this gives both platforms one machine readable
        // artifact to collect.
        ReactNativeBlobUtil.fs
          .writeFile(
            `${ReactNativeBlobUtil.fs.dirs.DocumentDir}/${RESULTS_FILE}`,
            JSON.stringify(
              {
                platform: Platform.OS,
                version: Platform.Version,
                ms: Date.now() - began,
                results: all,
              },
              null,
              2,
            ),
            'utf8',
          )
          .catch(() => {
            /* best effort */
          });
      }
    },
    [running],
  );

  const autoStarted = useRef(false);
  useEffect(() => {
    if (autoStarted.current) return;
    autoStarted.current = true;
    start(RUN_ON_LAUNCH);
  }, [start]);

  const summary = useMemo(
    () => ({
      passed: results.filter(r => r.status === 'pass').length,
      failed: results.filter(r => r.status === 'fail').length,
      skipped: results.filter(r => r.status === 'skip').length,
    }),
    [results],
  );

  const visible = useMemo(
    () => (filter === 'failed' ? results.filter(r => r.status === 'fail') : results),
    [results, filter],
  );

  const sections = useMemo(() => {
    const map = new Map<string, TestResult[]>();
    for (const result of visible) {
      const list = map.get(result.group);
      if (list) list.push(result);
      else map.set(result.group, [result]);
    }
    return Array.from(map.entries());
  }, [visible]);

  const expected = group
    ? results.length || total
    : total;
  const progress = expected > 0 ? Math.min(results.length / expected, 1) : 0;
  const ok = summary.failed === 0;

  return (
    <SafeAreaProvider>
      <SafeAreaView style={[styles.root, {backgroundColor: theme.bg}]} edges={['top', 'left', 'right']}>
        <View style={styles.header}>
          <View style={styles.headerRow}>
            <View style={styles.headerText}>
              <Text style={[styles.title, {color: theme.fg}]} numberOfLines={1}>
                react-native-sodium
              </Text>
              <Text style={[styles.subtitle, {color: theme.muted}]} numberOfLines={1}>
                {Platform.OS} {String(Platform.Version)} · {total} tests
                {group ? ` · ${group}` : ''}
              </Text>
            </View>
            <Pressable
              onPress={() => start(group)}
              disabled={running}
              style={[
                styles.button,
                {backgroundColor: running ? theme.disabled : theme.accent},
              ]}>
              {running ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.buttonText}>Run</Text>
              )}
            </Pressable>
          </View>

          <View style={[styles.track, {backgroundColor: theme.border}]}>
            <View
              style={[
                styles.trackFill,
                {
                  width: `${Math.round(progress * 100)}%`,
                  backgroundColor: summary.failed > 0 ? theme.fail : theme.pass,
                },
              ]}
            />
          </View>

          {results.length > 0 ? (
            <View style={styles.statsRow}>
              <Stat label="passed" value={summary.passed} color={theme.pass} />
              <Stat
                label="failed"
                value={summary.failed}
                color={summary.failed > 0 ? theme.fail : theme.muted}
              />
              <Stat label="skipped" value={summary.skipped} color={theme.muted} />
              <View style={styles.spacer} />
              <Text style={[styles.timing, {color: theme.muted}]}>
                {running
                  ? `${results.length}/${expected}`
                  : `${(elapsed / 1000).toFixed(1)}s`}
              </Text>
            </View>
          ) : null}

          {!running && results.length > 0 ? (
            <View
              style={[
                styles.verdict,
                {
                  backgroundColor: ok ? theme.passSoft : theme.failSoft,
                  borderColor: ok ? theme.pass : theme.fail,
                },
              ]}>
              <Text
                style={[styles.verdictText, {color: ok ? theme.pass : theme.fail}]}>
                {ok
                  ? 'All tests passed'
                  : `${summary.failed} failing`}
              </Text>
            </View>
          ) : null}
        </View>

        {/* flexGrow:0 keeps this row from being stretched to fill the column. */}
        <View style={styles.chipsRow}>
          <ScrollView
            horizontal
            showsHorizontalScrollIndicator={false}
            style={styles.chipsScroll}
            contentContainerStyle={styles.chipsContent}>
            <Chip
              label="all"
              active={group === undefined}
              disabled={running}
              theme={theme}
              onPress={() => start(undefined)}
            />
            {groups.map(name => (
              <Chip
                key={name}
                label={name}
                active={group === name}
                disabled={running}
                theme={theme}
                onPress={() => start(name)}
              />
            ))}
          </ScrollView>
        </View>

        {summary.failed > 0 ? (
          <View style={styles.filterRow}>
            {(['all', 'failed'] as Filter[]).map(value => (
              <Pressable
                key={value}
                onPress={() => setFilter(value)}
                style={[
                  styles.filterButton,
                  {
                    borderColor: theme.border,
                    backgroundColor:
                      filter === value ? theme.accentSoft : 'transparent',
                  },
                ]}>
                <Text style={[styles.filterText, {color: theme.fg}]}>
                  {value === 'all' ? `all ${results.length}` : `failed ${summary.failed}`}
                </Text>
              </Pressable>
            ))}
          </View>
        ) : null}

        <ScrollView style={styles.list} contentContainerStyle={styles.listContent}>
          {sections.map(([name, items]) => (
            <View key={name} style={styles.group}>
              <Text style={[styles.groupTitle, {color: theme.muted}]}>{name}</Text>
              {items.map((result, index) => (
                <View
                  key={`${name}::${result.name}::${index}`}
                  style={[styles.row, {borderColor: theme.border}]}>
                  <View
                    style={[
                      styles.dot,
                      {
                        backgroundColor:
                          result.status === 'pass'
                            ? theme.pass
                            : result.status === 'fail'
                            ? theme.fail
                            : theme.muted,
                      },
                    ]}
                  />
                  <View style={styles.rowBody}>
                    <Text style={[styles.name, {color: theme.fg}]}>
                      {result.name}
                    </Text>
                    {result.ms > 250 ? (
                      <Text style={[styles.ms, {color: theme.muted}]}>
                        {result.ms}ms
                      </Text>
                    ) : null}
                    {result.error ? (
                      <Text
                        selectable
                        style={[
                          styles.error,
                          {color: theme.fail, backgroundColor: theme.failSoft},
                        ]}>
                        {result.error}
                      </Text>
                    ) : null}
                  </View>
                </View>
              ))}
            </View>
          ))}
          {results.length === 0 && !running ? (
            <Text style={[styles.empty, {color: theme.muted}]}>
              No results yet. Tap Run.
            </Text>
          ) : null}
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <View style={styles.stat}>
      <Text style={[styles.statValue, {color}]}>{value}</Text>
      <Text style={[styles.statLabel, {color}]}>{label}</Text>
    </View>
  );
}

function Chip({
  label,
  active,
  disabled,
  theme,
  onPress,
}: {
  label: string;
  active: boolean;
  disabled: boolean;
  theme: typeof light;
  onPress: () => void;
}) {
  return (
    <Pressable
      disabled={disabled}
      onPress={onPress}
      style={[
        styles.chip,
        {
          borderColor: active ? theme.accent : theme.border,
          backgroundColor: active ? theme.accentSoft : 'transparent',
          opacity: disabled ? 0.5 : 1,
        },
      ]}>
      <Text
        numberOfLines={1}
        style={[styles.chipText, {color: active ? theme.accent : theme.fg}]}>
        {label}
      </Text>
    </Pressable>
  );
}

const light = {
  bg: '#ffffff',
  fg: '#101418',
  muted: '#6b7480',
  border: '#e2e6eb',
  disabled: '#b9c0c8',
  accent: '#2f6fed',
  accentSoft: '#e8f0fe',
  pass: '#137a45',
  passSoft: '#e9f6ee',
  fail: '#b3261e',
  failSoft: '#fdeceb',
};

const dark = {
  bg: '#0f1216',
  fg: '#e8eaed',
  muted: '#8a929c',
  border: '#282d34',
  disabled: '#3a4149',
  accent: '#6f9bff',
  accentSoft: '#17233c',
  pass: '#4fc98a',
  passSoft: '#12261b',
  fail: '#ff6f63',
  failSoft: '#2b1513',
};

const styles = StyleSheet.create({
  root: {flex: 1},
  header: {paddingHorizontal: 16, paddingTop: 8, paddingBottom: 4},
  headerRow: {flexDirection: 'row', alignItems: 'center', gap: 12},
  headerText: {flex: 1},
  title: {fontSize: 19, fontWeight: '700'},
  subtitle: {fontSize: 12, marginTop: 1},
  button: {
    minWidth: 72,
    height: 36,
    borderRadius: 8,
    alignItems: 'center',
    justifyContent: 'center',
  },
  buttonText: {color: '#ffffff', fontWeight: '600', fontSize: 14},
  track: {height: 3, borderRadius: 2, marginTop: 12, overflow: 'hidden'},
  trackFill: {height: 3, borderRadius: 2},
  statsRow: {flexDirection: 'row', alignItems: 'flex-end', gap: 16, marginTop: 10},
  stat: {flexDirection: 'row', alignItems: 'baseline', gap: 4},
  statValue: {fontSize: 16, fontWeight: '700'},
  statLabel: {fontSize: 11},
  spacer: {flex: 1},
  timing: {fontSize: 12, fontVariant: ['tabular-nums']},
  verdict: {
    marginTop: 10,
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  verdictText: {fontSize: 14, fontWeight: '700'},

  // Height is pinned so the horizontal list cannot stretch to fill the column.
  chipsRow: {height: 46, flexGrow: 0, flexShrink: 0},
  chipsScroll: {flexGrow: 0},
  chipsContent: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    gap: 8,
    alignItems: 'center',
  },
  chip: {
    height: 30,
    justifyContent: 'center',
    borderWidth: 1,
    borderRadius: 15,
    paddingHorizontal: 12,
  },
  chipText: {fontSize: 12, fontWeight: '500'},

  filterRow: {flexDirection: 'row', gap: 8, paddingHorizontal: 16, paddingBottom: 8},
  filterButton: {
    borderWidth: 1,
    borderRadius: 6,
    paddingHorizontal: 10,
    paddingVertical: 5,
  },
  filterText: {fontSize: 12},

  list: {flex: 1},
  listContent: {paddingHorizontal: 16, paddingBottom: 40},
  group: {marginBottom: 14},
  groupTitle: {
    fontSize: 11,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.7,
    marginBottom: 8,
  },
  row: {flexDirection: 'row', gap: 10, paddingVertical: 6, borderTopWidth: 1},
  dot: {width: 8, height: 8, borderRadius: 4, marginTop: 6},
  rowBody: {flex: 1},
  name: {fontSize: 14, lineHeight: 19},
  ms: {fontSize: 11, marginTop: 1},
  error: {
    fontSize: 11,
    marginTop: 6,
    padding: 8,
    borderRadius: 6,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    lineHeight: 15,
  },
  empty: {fontSize: 14, textAlign: 'center', marginTop: 40},
});
