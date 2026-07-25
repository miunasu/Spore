"""
CLI 测试命令 - 测试 episodic memory 的写入和检索
"""
import argparse
import json
from datetime import datetime
from pathlib import Path

from episode_store import EpisodeStore


def cmd_add(args):
    """添加测试 episode"""
    store = EpisodeStore(args.db)
    
    episode_id = store.add_episode(
        task_type=args.task_type,
        input_data={
            "user_query": args.query,
            "context": {}
        },
        output_data={
            "result": args.output
        },
        outcome=args.outcome,
        source="user",
        trust_zone="verified",
        salience=args.salience
    )
    
    print(f"Episode added: {episode_id}")


def cmd_get(args):
    """获取单条 episode"""
    store = EpisodeStore(args.db)
    
    episode = store.get_episode(args.episode_id)
    if episode:
        print(json.dumps(episode, indent=2, ensure_ascii=False))
    else:
        print(f"Episode not found: {args.episode_id}")


def cmd_list(args):
    """列出 episodes"""
    store = EpisodeStore(args.db)
    
    episodes = store.list_episodes(
        task_type=args.task_type,
        outcome=args.outcome,
        limit=args.limit
    )
    
    print(f"Found {len(episodes)} episodes:\n")
    for ep in episodes:
        print(f"[{ep['episode_id']}] {ep['timestamp']}")
        print(f"  Task: {ep['task_type']}")
        print(f"  Query: {ep['input'].get('user_query', 'N/A')}")
        print(f"  Outcome: {ep['outcome']}, Salience: {ep['salience']}")
        print()


def cmd_search(args):
    """检索相似 episodes"""
    store = EpisodeStore(args.db)
    
    results = store.search_similar(
        query=args.query,
        top_k=args.top_k,
        task_type=args.task_type
    )
    
    print(f"Found {len(results)} similar episodes:\n")
    for episode, score in results:
        print(f"[Score: {score:.3f}] {episode['episode_id']}")
        print(f"  Timestamp: {episode['timestamp']}")
        print(f"  Task: {episode['task_type']}")
        print(f"  Query: {episode['input'].get('user_query', 'N/A')}")
        print(f"  Outcome: {episode['outcome']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Episodic Memory CLI Test")
    parser.add_argument('--db', default='F:/friend/spore/memory/episodic.db',
                       help='Database path')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # add 命令
    add_parser = subparsers.add_parser('add', help='Add a test episode')
    add_parser.add_argument('--task-type', required=True, help='Task type')
    add_parser.add_argument('--query', required=True, help='User query')
    add_parser.add_argument('--output', required=True, help='Task output')
    add_parser.add_argument('--outcome', default='success',
                           choices=['success', 'partial', 'failed'])
    add_parser.add_argument('--salience', type=float, default=0.5,
                           help='Salience score (0-1)')
    add_parser.set_defaults(func=cmd_add)
    
    # get 命令
    get_parser = subparsers.add_parser('get', help='Get an episode by ID')
    get_parser.add_argument('episode_id', help='Episode ID')
    get_parser.set_defaults(func=cmd_get)
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='List episodes')
    list_parser.add_argument('--task-type', help='Filter by task type')
    list_parser.add_argument('--outcome', choices=['success', 'partial', 'failed'],
                            help='Filter by outcome')
    list_parser.add_argument('--limit', type=int, default=20, help='Max results')
    list_parser.set_defaults(func=cmd_list)
    
    # search 命令
    search_parser = subparsers.add_parser('search', help='Search similar episodes')
    search_parser.add_argument('query', help='Search query')
    search_parser.add_argument('--task-type', help='Filter by task type')
    search_parser.add_argument('--top-k', type=int, default=5, help='Number of results')
    search_parser.set_defaults(func=cmd_search)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    args.func(args)


if __name__ == '__main__':
    main()