# frozen_string_literal: true

module Rodauth
  module OAuth
    # rubocop:disable Naming/MethodName, Metrics/ParameterLists
    def self.ExtendDatabase(db)
      Module.new do
        dataset = db.dataset

        if dataset.supports_returning?(:insert)
          def __insert_and_return__(dataset, _pkey, params)
            dataset.returning.insert(params).first
          end
        else
          def __insert_and_return__(dataset, pkey, params)
            id = dataset.insert(params)
            dataset.where(pkey => id).first
          end
        end

        if dataset.supports_returning?(:update)
          def __update_and_return__(dataset, params)
            dataset.returning.update(params).first
          end
        else
          def __update_and_return__(dataset, params)
            dataset.update(params)
            dataset.first
          end
        end

        if dataset.respond_to?(:supports_insert_conflict?) && dataset.supports_insert_conflict?
          def __insert_or_update_and_return__(dataset, pkey, unique_columns, params, conds = nil, exclude_on_update = nil)
            to_update = params.keys - unique_columns
            to_update -= exclude_on_update if exclude_on_update

            dataset = dataset.insert_conflict(
              target: unique_columns,
              update: Hash[ to_update.map { |attribute| [attribute, Sequel[:excluded][attribute]] } ],
              update_where: conds
            )

            __insert_and_return__(dataset, pkey, params)
          end
        else
          def __insert_or_update_and_return__(dataset, pkey, unique_columns, params, conds = nil, exclude_on_update = nil)
            find_params, update_params = params.partition { |key, _| unique_columns.include?(key) }.map { |h| Hash[h] }

            dataset_where = dataset.where(find_params)
            record = if conds
                       dataset_where_conds = dataset_where.where(conds)

                       # this means that there's still a valid entry there, so return early
                       return if dataset_where.count != dataset_where_conds.count

                       dataset_where_conds.first
                     else
                       dataset_where.first
                     end

            if record
              update_params.reject! { |k, _v| exclude_on_update.include?(k) } if exclude_on_update
              __update_and_return__(dataset_where, update_params)
            else
              __insert_and_return__(dataset, pkey, params)
            end
          end
        end
      end
    end
    # rubocop:enable Naming/MethodName, Metrics/ParameterLists
  end
end
