"""只根据真实模型输出触发候选告警；不读取任何监督标签。"""
from netsentry.repositories.alert_repository import AlertRepository


class AlertService:
    def __init__(self, prediction: object, evidence: object, repository: AlertRepository) -> None:
        self.prediction=prediction;self.evidence=evidence;self.repository=repository

    def detect(self, record_ids: list[str], model_id: str) -> dict:
        if not 1<=len(record_ids)<=20:raise ValueError('批量大小须为1..20')
        result={'processed':0,'created':0,'duplicates':0,'below_threshold':0,'failures':[],'alerts':[]}
        for rid in record_ids:
            result['processed']+=1
            try:
                flow=self.evidence.flow(rid)
                prediction=self.prediction.predict(record_id=rid,model_id=model_id)
                if prediction['prediction']!='attack-related' or prediction['attack_related_score']<prediction['threshold']:
                    result['below_threshold']+=1;continue
                alert,created=self.repository.create(prediction,flow)
                result['created' if created else 'duplicates']+=1;result['alerts'].append(alert)
            except KeyError:
                result['failures'].append({'record_id':rid,'code':'not_found'})
            except ValueError:
                result['failures'].append({'record_id':rid,'code':'prediction_unavailable'})
        return result
