import json
import logging
import redis
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Initialize Redis client with socket timeout to prevent blocking during network issues
redis_client = redis.Redis(
    host="localhost",  # Change to "redis_cache" if running inside a Docker network
    port=6379,
    db=0,
    decode_responses=True,
    socket_timeout=2.0
)


def get_cached_schema(org_id: str, class_uid: int) -> Optional[Dict[str, Any]]:
    """Retrieve schema from Redis cache. Falls back gracefully on error."""
    cache_key = f"ocsf_schema:{org_id}:{class_uid}"
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except redis.RedisError as e:
        logger.warning(f"Redis GET failed for key {cache_key}: {e}. Falling back to DB.")
    return None


def set_cached_schema(org_id: str, class_uid: int, schema_data: Dict[str, Any], ttl: int = 3600) -> None:
    """Store schema in Redis cache with TTL. Fails gracefully on error."""
    cache_key = f"ocsf_schema:{org_id}:{class_uid}"
    try:
        redis_client.set(cache_key, json.dumps(schema_data), ex=ttl)
    except redis.RedisError as e:
        logger.warning(f"Redis SET failed for key {cache_key}: {e}.")


def invalidate_cached_schema(org_id: str, class_uid: int) -> None:
    """Evict schema key from Redis cache. Fails gracefully on error."""
    cache_key = f"ocsf_schema:{org_id}:{class_uid}"
    try:
        redis_client.delete(cache_key)
    except redis.RedisError as e:
        logger.warning(f"Redis DELETE failed for key {cache_key}: {e}.")


# Alias for backwards compatibility with any existing imports
delete_cached_schema = invalidate_cached_schema