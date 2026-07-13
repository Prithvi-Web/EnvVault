// Real password strength via zxcvbn (spec F1: "not a regex").
// Dictionaries are heavy, so they load lazily; the meter shows a neutral
// state for the few milliseconds before they arrive.

export interface Strength {
  /** 0 (terrible) … 4 (strong). */
  score: 0 | 1 | 2 | 3 | 4;
  warning: string | null;
}

type Scorer = (password: string) => Strength;

let scorer: Scorer | null = null;
let loading: Promise<void> | null = null;

export function loadScorer(): Promise<void> {
  loading ??= (async () => {
    const [core, common, en] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]);
    core.zxcvbnOptions.setOptions({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...en.dictionary },
    });
    scorer = (password) => {
      const r = core.zxcvbn(password);
      return { score: r.score, warning: r.feedback.warning ?? null };
    };
  })();
  return loading;
}

export function scorePassword(password: string): Strength | null {
  return scorer ? scorer(password) : null;
}

/** The bar a vault password must clear (spec F1: reject weak passwords). */
export const REQUIRED_SCORE = 3;

export const SCORE_LABELS = ["Too weak", "Weak", "Okay", "Good", "Strong"] as const;
