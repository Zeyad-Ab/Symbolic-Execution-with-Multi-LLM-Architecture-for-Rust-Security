# `graph_klee.py` (Neo4j graph build) usage

This tool parses a KLEE output directory and loads the results into Neo4j so you can query it with Cypher.

## Requirements

- Python 3.9+
- Neo4j running locally (Neo4j Desktop or Server)
- A KLEE output directory (e.g. `4agent_output/positive/klee_output/cwe-131-cve-2020-35904`)

## Setup (macOS/Homebrew Python)

Some macOS Python installations block system-wide `pip install`. Use a virtual environment:

```bash
cd "/path/to/your/repo"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

## Neo4j connection settings

Set these environment variables (or put them in your local `.env` file):

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="YOUR_PASSWORD"
export NEO4J_DATABASE="neo4j"
```

Notes:
- In Neo4j Desktop, the "DBMS instance name" is not always the database name.
- In Neo4j Community Edition, the database is typically `neo4j`.

## Run on a 4-agent KLEE output directory

```bash
. .venv/bin/activate
NEO4J_URI="bolt://localhost:7687" \
NEO4J_USER="neo4j" \
NEO4J_PASSWORD="YOUR_PASSWORD" \
NEO4J_DATABASE="neo4j" \
python3 graph_klee.py "4agent_output/positive/klee_output/cwe-131-cve-2020-35904"
```

The script will:
- Parse `test*.ktest`, `test*.kquery`, and `test*.err` files
- Insert nodes and relationships into Neo4j
- Write a local `vulnerability_report.json`

Important: The script clears the target database before inserting data:

```cypher
MATCH (n) DETACH DELETE n
```

## Cypher queries (Neo4j Browser)

Count nodes:

```cypher
MATCH (n) RETURN labels(n) AS labels, count(*) AS n ORDER BY n DESC;
```

Count errors by subtype:

```cypher
MATCH (e:Error)
RETURN e.subtype AS subtype, count(*) AS n
ORDER BY n DESC;
```

Top functions that trigger errors:

```cypher
MATCH (f:Function)-[:TRIGGERS]->(e:Error)
RETURN f.name AS function, count(e) AS errors
ORDER BY errors DESC
LIMIT 20;
```

Example execution paths:

```cypher
MATCH (t:TestCase)-[:EXECUTES]->(f:Function)-[:TRIGGERS]->(e:Error)
RETURN t.id AS test, f.name AS function, e.type AS type, e.subtype AS subtype
LIMIT 50;
```

