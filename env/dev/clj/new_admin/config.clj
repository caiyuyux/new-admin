(ns new-admin.config
  (:require [selmer.parser :as parser]
            [taoensso.timbre :as timbre]
            [new-admin.dev-middleware :refer [wrap-dev]]))

(def defaults
  {:init
   (fn []
     (parser/cache-off!)
     (timbre/info "\n-=[new-admin started successfully using the development profile]=-"))
   :middleware wrap-dev})
