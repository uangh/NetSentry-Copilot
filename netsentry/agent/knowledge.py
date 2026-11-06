"""小型可信本地知识检索：确定性切块、TF-IDF排序、内容寻址引用。"""
import hashlib
import json
from pathlib import Path
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .schemas import KnowledgeHit

ROOT=Path(__file__).resolve().parents[2]


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


class KnowledgeIndex:
    def __init__(self, documents: list[dict]) -> None:
        if not 1<=len(documents)<=100:raise ValueError('知识文档数量超限')
        self.chunks=[];ids=set()
        for doc in sorted(documents,key=lambda d:d['document_id']):
            if set(doc)!={'document_id','title','source_url','source_version','text'}:raise ValueError('知识来源字段不符')
            if doc['document_id'] in ids or len(doc['text'])>20000:raise ValueError('重复ID或文本过长')
            if not doc['source_url'].startswith('https://attack.mitre.org/'):raise ValueError('非批准来源')
            ids.add(doc['document_id']);sha=digest(doc)
            for i,paragraph in enumerate(re.split(r'\n\s*\n',doc['text'])):
                for j,start in enumerate(range(0,len(paragraph),800)):
                    text=paragraph[start:start+800].strip()
                    if text:self.chunks.append({k:v for k,v in doc.items() if k!='text'}|{
                        'chunk_id':f"{doc['document_id']}:{i}:{j}:{sha[:12]}",'document_sha256':sha,'text':text})
        self.vectorizer=TfidfVectorizer(lowercase=True,ngram_range=(1,2),token_pattern=r'(?u)\b\w+\b')
        self.matrix=self.vectorizer.fit_transform([c['text'] for c in self.chunks])

    @classmethod
    def default(cls) -> 'KnowledgeIndex':
        return cls(json.loads((ROOT/'knowledge/security_notes.json').read_text(encoding='utf-8')))

    def search(self, query: str, top_k: int=3) -> list[dict]:
        if not isinstance(query,str) or len(query)>300 or not 1<=top_k<=5:raise ValueError('检索预算/参数不符')
        scores=cosine_similarity(self.vectorizer.transform([query]),self.matrix)[0]
        ranked=sorted(range(len(scores)),key=lambda i:(-scores[i],self.chunks[i]['chunk_id']))
        return [KnowledgeHit.model_validate(self.chunks[i]|{'score':float(scores[i])}).model_dump()
                for i in ranked[:top_k] if scores[i]>0]

    def export(self) -> dict:
        return {'version':'netsentry.tfidf.v1','chunks':self.chunks,'vocabulary':self.vectorizer.vocabulary_,
                'idf':self.vectorizer.idf_.tolist(),'matrix':self.matrix.toarray().tolist(),
                'content_sha256':digest(self.chunks)}

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('x',encoding='utf-8') as file:json.dump(self.export(),file,ensure_ascii=False,sort_keys=True,indent=2)
