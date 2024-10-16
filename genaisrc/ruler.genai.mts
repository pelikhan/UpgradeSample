script({
  title: "ruler",
  parameters: {
    minInstances: {
      type: "number",
      description: "Minimum number of instances to analyze",
      default: 10,
    },
    maxInstances: {
      type: "number",
      description: "Maximum number of instances to analyze",
      default: 100,
    },
  },
});

const { minInstances, maxInstances } = env.vars;

type AzCatRule = {
  id: string;
  description: string;
  label: string;
  severity: string;
  links: { title: string; url: string }[];
};
type AzCatRuleInstance = {
  incidentId: string;
  ruleId: string;
  projectPath: string;
  state: "Active" | "Inactive";
  location: {
    kind: "File" | "Binary";
    path: string;
    snippet: string;
    protectedSnippet: string;
    label?: string;
    line?: number;
    column?: number;
  };
};
type AzCatReport = {
  settings: any;
  projects: {
    path: string;
    ruleInstances: AzCatRuleInstance[];
  }[];
  rules: Record<string, AzCatRule>;
};

const file = env.files[0] || "eShopLegacyMVC-no_dependencies.appcat.json";
const report: AzCatReport = await workspace.readJSON(file);
const { rules, projects } = report;
const dir = "net472";
console.log(`found ${projects.length} projects`);

// cluster by ruleInstance by ruleId
const ruleInstancesByRuleId: Record<string, AzCatRuleInstance[]> = {};
for (const project of projects) {
  for (const ruleInstance of project.ruleInstances) {
    if (!ruleInstancesByRuleId[ruleInstance.ruleId]) {
      ruleInstancesByRuleId[ruleInstance.ruleId] = [];
    }
    ruleInstancesByRuleId[ruleInstance.ruleId].push(ruleInstance);
  }
}
console.log(`found ${Object.keys(ruleInstancesByRuleId).length} active rules`);

// sort by number of instances
const sortedRules = Object.keys(rules).sort(
  (l, r) =>
    -(ruleInstancesByRuleId[l]?.length || 0) +
    (ruleInstancesByRuleId[r]?.length || 0)
);

// cluster by rules
for (const id of sortedRules) {
  const ruleInstances = ruleInstancesByRuleId[id];
  if (ruleInstances.length < minInstances) continue; // skip rules with less than minInstances

  const res = await runPrompt(
    async (_) => {
      _.$`Analyze the ERROR reported by the AzCAT tool.
        
        Cluster the ERROR in related groups by root cause and assign a label to each group.

        Report results in JSON.
        Validate JSON schema GROUPS_SCHEMA

        - do NOT invent incidentId values
        `;
      _.defSchema("GROUPS_SCHEMA", {
        type: "array",
        items: {
          type: "object",
          properties: {
            label: { type: "string" },
            rootCause: { type: "string" },
            incidentIds: {
              type: "array",
              items: {
                type: "string",
                description: "incidentId",
              },
            },
          },
        },
      });
      // random sampling when we have 15k rules?
      for (const ruleInstance of ruleInstances.slice(0, maxInstances)) {
        const { location, incidentId } = ruleInstance;
        _.def(
          "ERROR",
          {
            filename: path.join(dir, location.path),
            content: `// incidentId: ${incidentId}
            ${
              location.line
                ? `[${location.line}] ${location.snippet}`
                : location.snippet
            }`,
          },
          { flex: 1, lineNumbers: false }
        );
      }
    },
    {
      model: "large",
      cache: "rulerz",
      label: `rule ${id}, ${ruleInstances.length} instances`,
      flexTokens: 12000,
      system: [
        "system",
        "system.annotations",
        "system.schema",
        "system.files",
        "system.files_schema",
      ],
    }
  );

  // check return incident ids
  const frame = res.frames[0];
  if (!frame) {
    console.log(`no data for rule ${id}`);
    continue;
  }
  const data: {
    ruleId: string;
    label: string;
    rootCause: string;
    incidentIds: string[];
  }[] = frame.data as any;
  for (const group of data) {
    const incidents = group.incidentIds.slice(0);
    group.ruleId = id;
    group.incidentIds = [];
    for (const incidentId of incidents) {
      if (
        ruleInstances.find(
          (r) => r.incidentId.toLowerCase() === incidentId.toLowerCase()
        )
      ) {
        group.incidentIds.push(incidentId);
      } else console.warn(`incidentId ${incidentId} not found`);
    }
  }

  console.log(YAML.stringify(data));
}
