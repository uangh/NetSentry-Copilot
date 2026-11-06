"""Fixed retrieval relevance checks; distinct documents and chunks counted separately."""
from netsentry.agent.knowledge import KnowledgeIndex
QUERIES=(('authentication login failures credentials','ns-authentication-boundary'),
    ('network bandwidth availability health','ns-network-availability'),
    ('ports service discovery asset inventory','ns-service-discovery'),
    ('candidate evidence provenance review','ns-evidence-review'))

def evaluate_rag(index: KnowledgeIndex | None=None) -> dict:
    index=index or KnowledgeIndex.default();rows=[]
    for query,expected in QUERIES:
        hits=index.search(query,3)
        rows.append({'query':query,'expected_document':expected,'hit_at_3':any(h['document_id']==expected for h in hits),
            'unique_documents':len({h['document_id'] for h in hits}),'chunks':len(hits),
            'hits':[{'document_id':h['document_id'],'chunk_id':h['chunk_id'],'score':h['score'],
                     'relevance':'low' if h['score']<.15 else 'retrieval_match','source_sha256':h['document_sha256']} for h in hits]})
    return {'scope':'four fixed English project queries; expected document IDs, not attack attribution',
        'hit_at_3':{'numerator':sum(r['hit_at_3'] for r in rows),'denominator':len(rows)},'rows':rows,'knowledge_sha256':index.export()['content_sha256']}
