import requests
import json
import sys
import logging

class JIRA():

    def __init__(self, url, user, password):

        self.logger = logging.getLogger()
        self.logger.addHandler(logging.NullHandler())

        self.url = url
        self.user = user
        self.password = password

        self.transition_resolve = '111'
        self.transition_progress = '31'

        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-ExperimentalApi': 'opt-in'
        }

    def create_ticket(self, servicedesk_id, request_id, summary, desc, components, environment, prio):

        if servicedesk_id == '8':
            servicedesk_id = '9'

        data = {
            "serviceDeskId": servicedesk_id,
            "requestTypeId": request_id,
            "requestFieldValues": {
                "summary": summary,
                "description": desc,
                "components": components,
                "customfield_10502": {'value': environment},
                "priority": {"name": prio}
            }
        }

        self.logger.info('create ticket: ' + str(data))

        r = requests.post(self.url + '/rest/servicedeskapi/request', data=json.dumps(data), headers=self.headers, auth=(self.user, self.password))

        if r.status_code != 201:
            self.logger.error('failed to create ticket: ' + str(r.status_code) + ', ' + str(r.text))
            raise Exception(r.text)

        ticket_key = r.json()['issueKey']
        self.logger.info('successfully created ticket ' + ticket_key)
        return ticket_key

    def do_transition_progress(self, ticket_key, comment):

        data = {
          "update": {
            "comment": [
              {
                "add": {
                  "body": comment
                }
              }
            ]
          },
          "transition": {
            "id": self.transition_progress
          }
        }

        self.logger.info('transition ticket ' + ticket_key + ' to "in progress"')

        r = requests.post(self.url + '/rest/api/2/issue/' + ticket_key + '/transitions', data=json.dumps(data), headers=self.headers, auth=(self.user, self.password))
        
        if r.status_code != 204:
            self.logger.error('failed to transition: ' + str(r.status_code) + ', ' + str(r.text))
            raise Exception(r.text)

        self.logger.info('successfully transitioned ticket ' + ticket_key + ' to "in progress"')

    def do_transition_resolve(self, ticket_key, comment):

        data = {
          "update": {
            "comment": [
              {
                "add": {
                  "body": comment
                }
              }
            ]
          },
          "fields": {
            "resolution": {
              "name": "Done"
            }
          },
          "transition": {
            "id": self.transition_resolve
          }
        }

        self.logger.info('transition ticket ' + ticket_key + ' to "resolved"')

        r = requests.post(self.url + '/rest/api/2/issue/' + ticket_key + '/transitions', data=json.dumps(data), headers=self.headers, auth=(self.user, self.password))
        
        if r.status_code != 204:
            self.logger.error('failed to transition: ' + str(r.status_code) + ', ' + str(r.text))
            raise Exception('do_transition_resolve: ' + r.status_code + ' (' + r.text + ')')

        self.logger.info('successfully transitioned ticket ' + ticket_key + ' to "resolved"')

    def is_resolveable(self, ticket_key):

        r = requests.get(self.url + '/rest/api/2/issue/' + ticket_key + '/transitions', headers=self.headers, auth=(self.user, self.password))
        r.raise_for_status
        r_json = r.json()

        ir = len(list(filter(lambda x: x['id'] == self.transition_resolve, r_json['transitions']))) > 0

        if len(r_json['transitions']) == 0:
            self.logger.warning('is_resolveable: we have no possible transition, maybe permission problem')
        elif ir == 0:
            self.logger.debug(ticket_key + ' is not resolveable')
        else:
            self.logger.debug(ticket_key + ' is resolveable')

        return ir

    def is_progressable(self, ticket_key):

        r = requests.get(self.url + '/rest/api/2/issue/' + ticket_key + '/transitions', headers=self.headers, auth=(self.user, self.password))
        r.raise_for_status
        r_json = r.json()

        ip = len(list(filter(lambda x: x['id'] == self.transition_progress, r_json['transitions']))) > 0

        if len(r_json['transitions']) == 0:
            self.logger.warning('is_progressable: we have no possible transition, maybe permission problem')
        elif ip == 0:
            self.logger.debug(ticket_key + ' is not progressable')
        else:
            self.logger.debug(ticket_key + ' is progressable')

        return ip

